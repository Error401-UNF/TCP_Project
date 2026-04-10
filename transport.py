import socket
import struct
import threading
import time
from typing import Any  
from grading import MSS, DEFAULT_TIMEOUT, MAX_NETWORK_BUFFER, WINDOW_INITIAL_WINDOW_SIZE, WINDOW_INITIAL_SSTHRESH

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

class ReadMode:
    NO_FLAG = 0
    NO_WAIT = 1
    TIMEOUT = 2

class Packet:
    def __init__(self, seq=0, ack=0, flags=0, window=0, payload=b"", sack=0):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.window = window
        self.payload = payload
        self.sack = sack

    def encode(self):
        # Encode the packet header and payload into bytes
        header = struct.pack("!IIBHQH", self.seq, self.ack, self.flags, self.window, self.sack, len(self.payload))
        return header + self.payload

    @staticmethod
    def decode(data):
        # Decode bytes into a Packet object
        header_size = struct.calcsize("!IIBHQH")
        if len(data) < header_size:
            return None
        seq, ack, flags, window, sack, payload_len = struct.unpack("!IIBHQH", data[:header_size])
        payload = data[header_size : header_size + payload_len]
        return Packet(seq, ack, flags, window, payload, sack)


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

        # Congestion control (TCP Tahoe)
        self.cwnd = WINDOW_INITIAL_WINDOW_SIZE
        self.ssthresh = WINDOW_INITIAL_SSTHRESH
        self.buffered_data: dict[int, Packet] = {}
        self.buffered_data_size = 0
        self.acked_sequence_numbs: list = []

        self.window = {
            "last_ack": 0,            # Next seq expected from peer (receiving)
            "next_seq_expected": 0,   # Highest cumulative ACK received from peer (sending)
            "recv_buf": b"",          # In-order received data
            "recv_len": 0,            
            "messages_available": 0,  # Count of completed EOF-terminated messages
            "next_seq_to_send": 0,    # Pointer for next byte to send
            "base": 0,                # Oldest unacknowledged byte
            "peer_advertised": MAX_NETWORK_BUFFER 
        }
        self.sock_type = None
        self.conn = None

    def socket(self, sock_type, port, server_ip=None):
        """
        Create and initialize the socket, setting its type and starting the backend thread.
        """
        self.sock_fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_type = sock_type

        if sock_type == "TCP_INITIATOR":
            self.conn = (server_ip, port)
            self.sock_fd.bind(("", 0))
        elif sock_type == "TCP_LISTENER":
            self.sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_fd.bind(("", port))
        else:
            return EXIT_ERROR

        self.sock_fd.settimeout(1.0)
        self.thread = threading.Thread(target=self.backend, daemon=True)
        self.thread.start()
        return EXIT_SUCCESS

    def close(self):
        """
        Close the socket gracefully.
        """
        print(f"TCP {self.owner}: Closing...")
        time.sleep(2)
        with self.death_lock:
            self.dying = True
        if self.sock_fd:
            self.sock_fd.close()
        return EXIT_SUCCESS

    def update_rto(self, measured_rtt: float):
        """Implement EWMA for RTT estimation and RTO calculation

        Args:
            measured_rtt (float): rtt measured
        """
        if self.srtt is None:
            self.srtt = measured_rtt
            self.rttvar = measured_rtt / 2
        else:
            self.rttvar = (1 - BETA) * self.rttvar + BETA * abs(self.srtt - measured_rtt) # type: ignore
            self.srtt = (1 - ALPHA) * self.srtt + ALPHA * measured_rtt
        
        self.rto = self.srtt + max(0.01, 4 * self.rttvar)
        self.rto = max(0.1, min(self.rto, 2.0))

    def get_advertised_window(self):
        return max(0, MAX_NETWORK_BUFFER - self.window["recv_len"] - self.buffered_data_size)

    def send(self, data):
        if not self.conn:
            raise ValueError(f"TCP {self.owner}: Connection not established.")
        with self.send_lock:
            self.acked_sequence_numbs.clear()
            self.sent_times.clear()
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
            
            if self.window["recv_len"] > 0:
                # Data is avalable! consume the message
                read_len = min(self.window["recv_len"], length)
                buf[0] = self.window["recv_buf"][:read_len]
                self.window["recv_buf"] = self.window["recv_buf"][read_len:]
                self.window["recv_len"] -= read_len
                if self.window["messages_available"] > 0:
                    self.window["messages_available"] -= 1
                self.wait_cond.notify_all()
        return read_len

    def send_segment(self, data: Any):
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

                effective_window = min(self.cwnd, self.window["peer_advertised"])

                while (self.window["next_seq_to_send"] - self.window["base"]) < effective_window:
                    offset = self.window["next_seq_to_send"] - start_seq
                    if offset >= total_len:
                        break
                    
                    payload_len = min(MSS, total_len - offset)
                    curr_seq = self.window["next_seq_to_send"]

                    # Skip the sequence number
                    if curr_seq in self.acked_sequence_numbs:
                        self.window["next_seq_to_send"] += payload_len
                        print(f"TCP {self.owner}: skipped sequence no:{curr_seq}")
                        continue
                    print(f"TCP {self.owner}: Sending segment seq={curr_seq}, len={payload_len}")
                        
                    self.sent_times[curr_seq] = time.time()
                    chunk = data[offset : offset + payload_len]
                    segment = Packet(
                        seq=curr_seq, ack=self.window["last_ack"], flags=0, 
                        window=self.get_advertised_window(), payload=chunk
                    )
                    
                    self.sock_fd.sendto(segment.encode(), self.conn) # type: ignore
                    self.window["next_seq_to_send"] += payload_len

                if not self.wait_cond.wait(timeout=self.rto):
                    # TCP Tahoe Timeout: Multiplicative decrease + reset
                    self.ssthresh = max(2 * MSS, self.cwnd // 2)
                    self.cwnd = WINDOW_INITIAL_WINDOW_SIZE
                    print(f"TCP {self.owner}: Timeout! ssthresh={self.ssthresh}, cwnd={self.cwnd}")
                    self.window["next_seq_to_send"] = self.window["base"]

        self.send_eof_marker()
    
    def send_eof_marker(self):
        """Sends an eof marker to the reciever
        """
        seq_no = self.window["next_seq_to_send"]
        print(f"TCP {self.owner}: Sending EOF marker at seq={seq_no}")
        end_pkt = Packet(seq=seq_no, ack=self.window["last_ack"], flags=SYN_FLAG, 
                        window=self.get_advertised_window(), payload=b"eof")
        ack_goal = seq_no + len(b"eof")
        
        while True:
            self.sock_fd.sendto(end_pkt.encode(), self.conn) # type: ignore
            if self.wait_for_ack(ack_goal):
                self.window["next_seq_to_send"] += len(b"eof")
                print(f"TCP {self.owner}: EOF acknowledged")
                break
            else:
                # Treat EOF loss as a congestion signal as well
                self.ssthresh = max(2 * MSS, self.cwnd // 2)
                self.cwnd = WINDOW_INITIAL_WINDOW_SIZE

    def wait_for_ack(self, ack_goal: float) -> bool:
        """waits for an acknologment for a specific amount of time

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
        """The process of capturing and understanding any packets deleverd into the system."""
        while not self.dying and self.sock_fd:
            try:
                raw_data, addr = self.sock_fd.recvfrom(2048)
                if self.conn is None:
                    self.conn = addr
                
                packet = Packet.decode(raw_data)
                if not packet: continue

                with self.recv_lock:
                    self.window["peer_advertised"] = packet.window
                    
                    # 1. Handle incoming ACKs (Sender Path)
                    if (packet.flags & ACK_FLAG) != 0:
                        if packet.ack > self.window["base"]:
                            # Congestion Control update
                            if self.cwnd < self.ssthresh:
                                # Slow Start
                                self.cwnd += MSS
                            else:
                                # Congestion Avoidance
                                self.cwnd += (MSS**2) / self.cwnd
                            
                            for seq in list(self.sent_times.keys()):
                                if seq < packet.ack:
                                    self.update_rto(time.time() - self.sent_times[seq])
                                    del self.sent_times[seq]
                                    self.acked_sequence_numbs.append(seq)
                            self.window["base"] = packet.ack
                            self.window["next_seq_expected"] = packet.ack
                            self.wait_cond.notify_all()
                    
                    # 2. Handle incoming data (Receiver Path)
                    if packet.payload or (packet.flags & SYN_FLAG) != 0:
                        if packet.seq == self.window["last_ack"]:
                            if self.window["recv_len"] + self.buffered_data_size + len(packet.payload) <= MAX_NETWORK_BUFFER:
                                if (packet.flags & SYN_FLAG) == 0:
                                    self.window["recv_buf"] += packet.payload
                                    self.window["recv_len"] += len(packet.payload)
                                    self.window["last_ack"] += len(packet.payload)
                                else:
                                    self.window["last_ack"] += len(packet.payload)
                                    self.window["messages_available"] += 1
                                
                                while self.window["last_ack"] in self.buffered_data:
                                    p = self.buffered_data.pop(self.window["last_ack"])
                                    self.buffered_data_size -= len(p.payload)
                                    self.window["recv_buf"] += p.payload
                                    self.window["recv_len"] += len(p.payload)
                                    self.window["last_ack"] += len(p.payload)
                                self.packet_cond.notify_all()
                        else:
                            if self.window["last_ack"] < packet.seq and \
                               self.window["recv_len"] + self.buffered_data_size + len(packet.payload) <= MAX_NETWORK_BUFFER:
                                if packet.seq not in self.buffered_data:
                                    self.buffered_data[packet.seq] = packet
                                    self.buffered_data_size += len(packet.payload)

                        ack_pkt = Packet(seq=0, ack=self.window["last_ack"], flags=ACK_FLAG, 
                                        window=self.get_advertised_window())
                        self.sock_fd.sendto(ack_pkt.encode(), addr)

            except socket.timeout:
                continue
            except Exception:
                break