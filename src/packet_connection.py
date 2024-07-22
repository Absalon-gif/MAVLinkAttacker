import socket
import os
import threading
from datetime import datetime

MAVLINK_START_BYTE = '0xFE'


packet_dict = {
    "packet_id": None,
    "timestamp": None,
    "source_ip": None,
    "destination_ip": None,
    "length": None,
    "mavlink_messages": [
        {
            "system_id": None,
            "component_id": None,
            "msg_id": None,
            "payload": None
        }
    ]
}


class PacketSniffer:
    current_packet_id = 0

    def __init__(self, network_interface, log_function):
        self.network_interface = network_interface
        self.log_function = log_function
        self.sniffer = None
        self.stop_event = threading.Event()

    def start_sniffing(self, ):
        try:
            self.sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.sniffer.bind((self.network_interface, 0))
            os.system(f"ip link set {self.network_interface} promisc on")

            while not self.stop_event.is_set():
                try:
                    raw_packet, addr = self.sniffer.recvfrom(65565)
                    if PacketAnalyzer.is_mavlink_packet(raw_packet):
                        print(f"Captured MAVLINK packet: {raw_packet}; Address stuff: {addr}")
                        self.log_function(f"Captured MAVLink packet: {raw_packet[:16]}; Address stuff: {addr}")
                except socket.error as e:
                    self.log_function(f"Socket Error: {e}")
                    break
        except KeyboardInterrupt:
            self.clean()
        except Exception as e:
            self.log_function(f"Exception while starting sniffing: {e}")
            print(f"Exception while starting sniffing: {e}")
        finally:
            self.clean()

    def create_packet(self, mav_packet, addr):
        PacketSniffer.current_packet_id += 1

        return {
            "packet_id": PacketSniffer.current_packet_id,
            "timestamp": datetime.now().isoformat(),
            "source_ip": addr[0],
            "destination_ip": addr[1],
            "length": len(mav_packet),
        }

    def stop_sniffing(self):
        self.stop_event.set()
        if self.sniffer:
            self.sniffer.close()

    def clean(self):
        os.system(f"ip link set {self.network_interface} promisc off")
        if self.sniffer:
            self.sniffer.close()


class PacketAnalyzer:
    def __init__(self):
        self.captured_packets = None

    @staticmethod
    def is_mavlink_packet(packet) -> bool:
        if packet[0] == MAVLINK_START_BYTE:
            return True
        return False
