import socket
import struct
import threading
import time
from typing import Any  
from grading import MSS, DEFAULT_TIMEOUT, MAX_NETWORK_BUFFER

# Constants for simplified TCP
SYN_FLAG = 0x8   # Synchronization flag 
ACK_FLAG = 0x4   # Acknowledgment flag
FIN_FLAG = 0x2   # Finish flag 
SACK_FLAG = 0x1  # Selective Acknowledgment flag 

EXIT_SUCCESS = 0
EXIT_ERROR = 1

MAX_MESSAGE_TIME = 2.0

# EWMA Constants
ALPHA = 0.125
BETA = 0.25

# keep untouched
class ReadMode:
    NO_FLAG = 0
    NO_WAIT = 1
    TIMEOUT = 2

# keep untouched
class Packet:
    def __init__(self, seq=0, ack=0, flags=0, window = 0, payload=b"",sack=0):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.window = window
        self.payload = payload
        self.sack = sack
    def encode(self):
        # Encode the packet header and payload into bytes
        header = struct.pack("!IIBHQH", self.seq, self.ack, self.flags, self.window, self.sack,len(self.payload))
        return header + self.payload

    @staticmethod
    def decode(data):
        # Decode bytes into a Packet object
        header_size = struct.calcsize("!IIBHQH")
        seq, ack, flags, window, sack, payload_len = struct.unpack("!IIBHQH", data[:header_size])
        payload = data[header_size:]
        return Packet(seq, ack, flags, window, payload,sack)


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

        # RTT Estimation State
        self.rto = float(DEFAULT_TIMEOUT) 
        self.srtt = None
        self.rttvar = None
        self.sent_times = {}

        self.window = {
            "last_ack": 0,            # The next seq we expect from peer (receiving)
            "last_ack_time": time.time(),
            "next_seq_expected": 0,   # The highest ack we've received for our data
            "recv_buf": b"",          # Received data buffer
            "recv_len": 0,            
            "messages_available": 0,  # Count of completed EOF-terminated messages
            "next_seq_to_send": 0,    # Pointer for next byte to send
            "base": 0,                # Oldest unacknowledged byte
            "current_window": MSS,    # Start with 1 MSS (AIMD growth)
            "peer_advertised": MAX_NETWORK_BUFFER # What the peer says they can handle
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

    def update_rto(self, measured_rtt: float):
        """Implement EWMA for RTT estimation and RTO calculation

        Args:
            measured_rtt (float): rtt measured
        """
        if self.srtt is None:
            # Initial measurement
            self.srtt = measured_rtt
            self.rttvar = measured_rtt / 2
        else:
            # math to figure out next expected time
            self.rttvar = (1 - BETA) * self.rttvar + BETA * abs(self.srtt - measured_rtt) # type: ignore
            self.srtt = (1 - ALPHA) * self.srtt + ALPHA * measured_rtt
        
        self.rto = self.srtt + max(0.01, 4 * self.rttvar)
        # Force rto to be resionable
        self.rto = max(0.1, min(self.rto, 2.0))
        print(f"TCP {self.owner}: Updated RTO: {self.rto:.4f}s (RTT: {measured_rtt:.4f}s)")
    
    def send(self, data):
        """
        Send data reliably to the peer (stop-and-wait style).
        """
        if not self.conn:
            raise ValueError(f"TCP {self.owner}: Connection not established.")
        with self.send_lock:
            self.send_segment(data)

    def recv(self, buf: list, length: int, flags: int) -> int:
        """Receves 1 file from the tcp system

        Args:
            buf (list): local buffer
            length (int): max length of content to retrieve
            flags (int): flags sent to the system

        Returns:
            int: length of output
        """
        read_len = 0
        with self.packet_cond:
            if flags == ReadMode.NO_FLAG:
                # Enforce assumption: Wait until at least ONE full message (ended by EOF) is ready
                while self.window["messages_available"] == 0:
                    if not self.packet_cond.wait(timeout=1.0):
                        with self.death_lock:
                            if self.dying: return 0
                print(f"TCP {self.owner}: recv block released")
            
            if self.window["recv_len"] > 0:
                # We return the data available in the buffer. 
                # Note: In a strictly 1-send-1-recv setup, we assume the application 
                # wants the whole message.
                read_len = min(self.window["recv_len"], length)
                buf[0] = self.window["recv_buf"][:read_len]
                self.window["recv_buf"] = self.window["recv_buf"][read_len:]
                self.window["recv_len"] -= read_len
                
                # Consume one message credit
                if self.window["messages_available"] > 0:
                    self.window["messages_available"] -= 1
                
                print(f"TCP {self.owner}: read {read_len} bytes from buffer, {self.window['recv_len']} remaining")
                # After consumption, notify backend/sender that window space may have opened
                self.wait_cond.notify_all()
        return read_len

    def get_advertised_window(self):
        """ Calculate remaining buffer space for Flow Control """
        return max(0, MAX_NETWORK_BUFFER - self.window["recv_len"])

    def send_segment(self, data:Any):
        """sends data as a bunch of segments.

        Args:
            data (Any): binary data to send
        """
        start_seq = self.window["next_seq_to_send"]
        total_len = len(data)

        while True:
            with self.recv_lock:
                if (self.window["base"] - start_seq) >= total_len:
                    break

                effective_window = min(self.window["current_window"], self.window["peer_advertised"])

                while (self.window["next_seq_to_send"] - self.window["base"]) < effective_window:
                    offset = self.window["next_seq_to_send"] - start_seq
                    if offset >= total_len:
                        break
                    
                    payload_len = min(MSS, total_len - offset)
                    chunk = data[offset : offset + payload_len]
                    
                    curr_seq = self.window["next_seq_to_send"]
                    print(f"TCP {self.owner}: Sending segment seq={curr_seq}, len={payload_len}")
                    
                    # Store time for RTT estimation
                    self.sent_times[curr_seq] = time.time()
                    
                    segment = Packet(
                        seq=curr_seq, 
                        ack=self.window["last_ack"], 
                        flags=0, 
                        window=self.get_advertised_window(),
                        payload=chunk
                    )
                    
                    self.sock_fd.sendto(segment.encode(), self.conn) # type: ignore
                    self.window["next_seq_to_send"] += payload_len

                # Wait using the dynamic RTO
                if not self.wait_cond.wait(timeout=self.rto):
                    # Timeout occurred - Karn's algorithm: don't update RTT on retransmission
                    # Clear sent_times for unacked data to avoid false RTT samples
                    self.sent_times.clear()
                    self.window["current_window"] = max(MSS, self.window["current_window"] // 2)
                    print(f"TCP {self.owner}: Timeout! New Window: {self.window['current_window']}, RTO: {self.rto:.4f}")
                    self.window["next_seq_to_send"] = self.window["base"]

        self.send_eof_marker()
    
    def send_eof_marker(self):
        seq_no = self.window["next_seq_to_send"]
        print(f"TCP {self.owner}: Sending EOF marker at seq={seq_no}")
        end_pkt = Packet(seq=seq_no, ack=self.window["last_ack"], flags=SYN_FLAG, window=self.get_advertised_window(), payload=b"eof")
        ack_goal = seq_no + len(b"eof")
        
        while True:
            self.sock_fd.sendto(end_pkt.encode(), self.conn) # type: ignore
            if self.wait_for_ack(ack_goal):
                self.window["next_seq_to_send"] += len(b"eof")
                print(f"TCP {self.owner}: EOF acknowledged")
                break
            else:
                print(f"TCP {self.owner}: EOF timeout, retrying...")

    def wait_for_ack(self, ack_goal: float) -> bool:
        """_summary_

        Args:
            ack_goal (float): how long to wait

        Returns:
            bool: ack returned or not
        """
        with self.recv_lock:
            start = time.time()
            while self.window["next_seq_expected"] < ack_goal:
                remaining = self.rto - (time.time() - start)
                if remaining <= 0 or not self.wait_cond.wait(timeout=remaining):
                    return False
            return True

    def backend(self):
        """the process of capturing and understanding any packets deleverd into the system."""
        while not self.dying and self.sock_fd != None:
            try:
                raw_data, addr = self.sock_fd.recvfrom(1024)
                if self.conn is None:
                    self.conn = addr
                
                packet = Packet.decode(raw_data)
                if not packet: continue

                should_ack = False
                ack_to_send = 0

                with self.recv_lock:
                    self.window["peer_advertised"] = packet.window
                    
                    # 1. Handle incoming ACKs
                    if (packet.flags & ACK_FLAG) != 0:
                        if packet.ack > self.window["base"]:
                            for seq in list(self.sent_times.keys()):
                                if seq < packet.ack:
                                    # relcalculate rto
                                    measured_rtt = time.time() - self.sent_times[seq]
                                    self.update_rto(measured_rtt)
                                    # Clear all samples before this ack
                                    del self.sent_times[seq]
                            # update window
                            self.window["current_window"] += MSS
                            self.window["base"] = packet.ack
                            self.window["next_seq_expected"] = packet.ack
                            self.wait_cond.notify_all()
                    
                    # 2. Handle incoming data/markers
                    if packet.payload or (packet.flags & SYN_FLAG) != 0:
                        if packet.seq == self.window["last_ack"]:
                            if (packet.flags & SYN_FLAG) == 0:
                                # regular data packet
                                if self.window["recv_len"] + len(packet.payload) <= MAX_NETWORK_BUFFER:
                                    self.window["recv_buf"] += packet.payload
                                    self.window["recv_len"] += len(packet.payload)
                                    self.window["last_ack"] += len(packet.payload)
                            else:
                                # end of file
                                self.window["last_ack"] += len(packet.payload)
                                self.window["messages_available"] += 1
                            self.packet_cond.notify_all()
                        ack_to_send = self.window["last_ack"]
                
                        # send ack
                        ack_pkt = Packet(seq=0, ack=ack_to_send, flags=ACK_FLAG, window=self.get_advertised_window())
                        self.sock_fd.sendto(ack_pkt.encode(), addr)
            except socket.timeout:
                continue
            except Exception as e:
                if not self.dying:
                    print(f"TCP {self.owner}: Backend exception: {e}")
                break