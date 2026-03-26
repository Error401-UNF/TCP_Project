import socket
import struct
import threading
import time  
from grading import MSS, DEFAULT_TIMEOUT

# Constants for simplified TCP
SYN_FLAG = 0x8   # Synchronization flag 
ACK_FLAG = 0x4   # Acknowledgment flag
FIN_FLAG = 0x2   # Finish flag 
SACK_FLAG = 0x1  # Selective Acknowledgment flag 

EXIT_SUCCESS = 0
EXIT_ERROR = 1

MAX_MESSAGE_TIME = 2.0

# keep untouched
class ReadMode:
    NO_FLAG = 0
    NO_WAIT = 1
    TIMEOUT = 2

# keep untouched
class Packet:
    def __init__(self, seq=0, ack=0, flags=0, payload=b""):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.payload = payload

    def encode(self):
        # Encode the packet header and payload into bytes
        header = struct.pack("!IIIH", self.seq, self.ack, self.flags, len(self.payload))
        return header + self.payload

    @staticmethod
    def decode(data):
        # Decode bytes into a Packet object
        header_size = struct.calcsize("!IIIH")
        seq, ack, flags, payload_len = struct.unpack("!IIIH", data[:header_size])
        payload = data[header_size:]
        return Packet(seq, ack, flags, payload)


class TransportSocket:
    def __init__(self):
        self.sock_fd = None

        # Locks and condition
        self.recv_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.wait_cond = threading.Condition(self.recv_lock)
        self.packet_cond = threading.Condition(self.recv_lock)

        self.death_lock = threading.Lock()
        self.dying = False
        self.thread = None
        self.owner = "Null"

        # sliding window method
        self.window = {
            "last_ack": 0,            # The next seq we expect from peer (used for receiving data)
            "last_ack_time": time.time(),     # Time since last packet
            "next_seq_expected": 0,   # The highest ack we've received for *our* transmitted data
            "recv_buf": b"",          # Received data buffer
            "recv_len": 0,            # How many bytes are in recv_buf
            "next_seq_to_send": 0,    # The sequence number for the next packet we send
        }
        self.sock_type = None
        self.conn = None
        self.my_port = None

    def socket(self, sock_type, port, server_ip=None):
        """
        Create and initialize the socket, setting its type and starting the backend thread.
        """
        self.sock_fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_type = sock_type

        if sock_type == "TCP_INITIATOR":
            self.conn = (server_ip, port)
            self.sock_fd.bind(("", 0))  # Bind to any available local port
        elif sock_type == "TCP_LISTENER":
            self.sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_fd.bind(("", port))
        else:
            print(f"TCP {self.owner}: Unknown socket type")
            return EXIT_ERROR

        # 1-second timeout so we can periodically check `self.dying`
        self.sock_fd.settimeout(1.0)

        self.my_port = self.sock_fd.getsockname()[1]

        # Start the backend thread
        self.thread = threading.Thread(target=self.backend, daemon=True)
        self.thread.start()
        return EXIT_SUCCESS

    def close(self):
        """
        Close the socket gracefully.
        """
        print(f"TCP {self.owner}: Closing...")
        
        # Wait a bit before setting self.dying. 
        # This keeps the backend thread alive to ACK any repeated EOFs 
        # the server might send if our first ACK was lost.
        time.sleep(2)

        with self.death_lock:
            self.dying = True

        if self.thread:
            self.thread.join()

        if self.sock_fd:
            self.sock_fd.close()
        
        return EXIT_SUCCESS

    # edited
    def send(self, data):
        """
        Send data reliably to the peer (stop-and-wait style).
        """
        if not self.conn:
            raise ValueError(f"TCP {self.owner}: Connection not established.")
        with self.send_lock:
            self.send_segment(data)

    def recv(self, buf, length, flags):
        """
        Retrieve received data from the buffer, with optional blocking behavior.

        :param buf: Buffer to store received data (list of bytes or bytearray).
        :param length: Maximum length of data to read
        :param flags: ReadMode flag to control blocking behavior
        :return: Number of bytes read

        **TO BE REWORKED**
        """
        read_len = 0

        if length < 0:
            print(f"TCP {self.owner}: ERROR: Negative length")
            return EXIT_ERROR

        # Always blocking read,
        with self.packet_cond:
            if flags == ReadMode.NO_FLAG:
                while self.window["recv_len"] == 0:
                    print(f"TCP {self.owner}: timeout lock aquired")
                    self.packet_cond.wait()    
                print(f"TCP {self.owner}: recv block released")

            
            if flags in [ReadMode.NO_WAIT, ReadMode.NO_FLAG]:
                if self.window["recv_len"] > 0:
                    read_len = min(self.window["recv_len"], length)
                    buf[0] = self.window["recv_buf"][:read_len]

                    # Remove data from the buffer
                    if read_len < self.window["recv_len"]:
                        self.window["recv_buf"] = self.window["recv_buf"][read_len:]
                        self.window["recv_len"] -= read_len
                    else:
                        self.window["recv_buf"] = b""
                        self.window["recv_len"] = 0
            else:
                print(f"TCP {self.owner}: ERROR: Unknown or unimplemented flag.")
                read_len = EXIT_ERROR
        return read_len

    def send_segment(self, data):
        """
        Send 'data' in multiple MSS-sized segments and reliably wait for each ACK
        """
        offset = 0
        total_len = len(data)

        # While there's data left to send
        while offset < total_len:
            payload_len = min(MSS, total_len - offset)

            # Current sequence number
            seq_no = self.window["next_seq_to_send"]
            chunk = data[offset : offset + payload_len]

            # Create a packet
            segment = Packet(seq=seq_no, ack=self.window["last_ack"], flags=0, payload=chunk)

            # We expect an ACK for seq_no + payload_len
            ack_goal = seq_no + payload_len

            while  self.sock_fd != None:
                print(f"TCP {self.owner}: Sending segment (seq={seq_no}, len={payload_len})")
                self.sock_fd.sendto(segment.encode(), self.conn)  # type: ignore # if this errors remove this and analyze issue

                if self.wait_for_ack(ack_goal):
                    print(f"TCP {self.owner}: Segment {seq_no} acknowledged.")
                    # Advance our next_seq_to_send
                    self.window["next_seq_to_send"] += payload_len
                    break
                else:
                    print(f"TCP {self.owner}: Timeout: Retransmitting segment.")

            offset += payload_len

        # end with a syn flag send
        seq_no = self.window["next_seq_to_send"]
        chunk = b"eof"
        end_pkt = Packet(seq=seq_no, ack=self.window["last_ack"], flags=SYN_FLAG, payload=chunk)
        payload_len = len(chunk)
        ack_goal = seq_no + payload_len
        while  self.sock_fd != None:
            print(f"TCP {self.owner}: Sending eof (seq={seq_no}, len={payload_len})")
            self.sock_fd.sendto(end_pkt.encode(), self.conn)  # type: ignore # if this errors remove this and analyze issue

            if self.wait_for_ack(ack_goal):
                print(f"TCP {self.owner}: eof {seq_no} acknowledged.")
                # Advance our next_seq_to_send
                self.window["next_seq_to_send"] += payload_len
                break
            else:
                print(f"TCP {self.owner}: Timeout: Retransmitting eof.")

    def wait_for_ack(self, ack_goal):
        """
        Wait for 'next_seq_expected' to reach or exceed 'ack_goal' within DEFAULT_TIMEOUT.
        Return True if ack arrived in time; False on timeout.
        """
        with self.recv_lock:
            start = time.time()
            while self.window["next_seq_expected"] < ack_goal:
                elapsed = time.time() - start
                remaining = DEFAULT_TIMEOUT - elapsed
                if remaining <= 0: # DEFAULT_TIMEOUT - (time.time() - start) <= 0
                    return False

                self.wait_cond.wait(timeout=remaining)

            return True

    def backend(self):
        """
        Backend loop to handle receiving data and sending acknowledgments.
        All incoming packets are read in this thread only, to avoid concurrency conflicts.
        """
        while not self.dying and self.sock_fd != None:
            try:
                data, addr = self.sock_fd.recvfrom(2048)
                packet = Packet.decode(data)

                # If no peer is set, establish connection (for listener)
                if self.conn is None:
                    self.conn = addr

                # If it's an ACK packet, update our sending side
                if (packet.flags & ACK_FLAG) != 0:
                    with self.recv_lock:
                        if packet.ack > self.window["next_seq_expected"]:
                            self.window["next_seq_expected"] = packet.ack
                        self.wait_cond.notify_all()
                    continue

                # Otherwise, assume it is a data packet
                # Check if the sequence matches our 'last_ack' (in-order data)
                if packet.seq == self.window["last_ack"]:
                    with self.recv_lock:
                        # Append payload to our receive buffer
                        if (packet.flags & SYN_FLAG) == 0: # dont do this for eof packet
                            self.window["recv_buf"] += packet.payload
                            self.window["recv_len"] += len(packet.payload)

                        
                        print(f"TCP {self.owner}: Received segment {packet.seq} with {len(packet.payload)} bytes.")

                        # Send back an acknowledgment
                        ack_val = packet.seq + len(packet.payload)
                        ack_packet = Packet(seq=0, ack=ack_val, flags=ACK_FLAG)
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        # Update last_ack
                        self.window["last_ack"] = ack_val
                        self.window["last_ack_time"] = time.time()

                        # if last packet in group notify
                        if (packet.flags & SYN_FLAG) != 0:
                            # end of send
                            print(f"TCP {self.owner}: eof detected!")
                            self.packet_cond.notify_all()
                else:
                    # For a real TCP, we need to send duplicate ACK or ignore out-of-order data
                    print(f"TCP {self.owner}: Out-of-order packet: seq={packet.seq}, expected={self.window['last_ack']}")
                    ack_packet = Packet(seq=0, ack=self.window["last_ack"], flags=ACK_FLAG)
                    self.sock_fd.sendto(ack_packet.encode(), addr)
                    """
                    if packet.seq < self.window['last_ack']:
                        # past packet. ack it and leave
                        with self.recv_lock:
                        # Append payload to our receive buffer
                        
                            print(f"TCP {self.owner}: send ack for {packet.seq} with {len(packet.payload)} bytes.")

                            # Send back an acknowledgment
                            ack_val = packet.seq + len(packet.payload)
                            ack_packet = Packet(seq=0, ack=ack_val, flags=ACK_FLAG)
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                            # Update last_ack
                            self.window["last_ack"] = ack_val
                            self.window["last_ack_time"] = time.time()

                            # if last packet in group notify
                            if (packet.flags & SYN_FLAG) != 0:
                                # end of send
                                print(f"TCP {self.owner}: eof detected!")
                                self.packet_cond.notify_all()
                    """

            except socket.timeout:
               continue
        
            except Exception as e:
                if not self.dying:
                    print(f"TCP {self.owner}: Error in backend: {e}")

