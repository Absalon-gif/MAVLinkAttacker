import socket
import struct
import threading
from datetime import datetime
from src.sniffer.packet_storage import PacketStorage

MAVLINK_START_BYTE = '0xFE'


BLOCKED_PORTS = {53, 67, 68, 123}


def convert_byte_to_mac_string(byte):
    converted_string = ':'.join(f'{byte:02x}' for byte in byte)
    return converted_string


class PacketSniffer:
    current_packet_id = 0

    def __init__(self, network_interface, log_function):
        self.network_interface = network_interface
        self.log_function = log_function
        self.sniffer = None
        self.stop_event = threading.Event()

    def start_sniffing(self):
        try:
            self.sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            print("Sniffer started")
            self.sniffer.bind((self.network_interface, 0))
            print("Sniffer binding")
            attacker_ip_address = self.get_ipaddr()
            while not self.stop_event.is_set():
                try:
                    raw_packet, addr = self.sniffer.recvfrom(65565)
                    eth_protocol = int.from_bytes(raw_packet[12:14], byteorder='big')
                    type_protocol = raw_packet[23:24].hex()
                    src_udp_port = int.from_bytes(raw_packet[34:36], byteorder='big')
                    dest_udp_port = int.from_bytes(raw_packet[36:38], byteorder='big')
                    if eth_protocol != 0x0800:
                        continue
                    if socket.inet_ntoa(raw_packet[30:34]) == attacker_ip_address or socket.inet_ntoa(
                            raw_packet[26:30]) == attacker_ip_address:
                        continue
                    if src_udp_port in BLOCKED_PORTS or dest_udp_port in BLOCKED_PORTS:
                        continue
                    if type_protocol == '11':
                        self.log_function("Captured Packet")
                        print("Captured Packet")
                        print(raw_packet)
                        PacketStorage.store_packet(self.create_packet(raw_packet))
                except socket.error as e:
                    self.log_function(f"Socket Error: {e}")
                    break
        except KeyboardInterrupt:
            self.clean()
        except Exception as e:
            self.log_function(f"Exception while starting sniffing: {e}")
            print(f"Exception while starting sniffing: {e}")
            self.clean()
        finally:
            self.clean()

    @staticmethod
    def get_ipaddr():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.168.4.1", 0))
            ip_address = s.getsockname()[0]
            s.close()
            return ip_address
        except Exception as e:
            print(f"Exception while getting ip address: {e}")


    @staticmethod
    def create_packet(mav_packet):
        PacketSniffer.current_packet_id += 1

        # Ethernet Header
        ethernet_header = mav_packet[:14]
        ethernet_frame = struct.unpack('!6s6sH', ethernet_header)

        # IP Header
        ip_header = mav_packet[14:34]
        ip_frame = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = ip_frame[0]
        ihl = version_ihl & 0xF
        ip_frame_length = ihl * 4

        #UDP Header
        udp_start = 14 + ip_frame_length
        udp_header = mav_packet[udp_start:udp_start + 8]
        udp_frame = struct.unpack('!HHHH', udp_header)

        #UDP Payload
        udp_payload_start = udp_start + 8
        udp_payload = mav_packet[udp_payload_start:]
        udp_payload_length = len(udp_payload)



        return {
            "packet_id": PacketSniffer.current_packet_id,
            "timestamp": datetime.now().isoformat(),
            "ethernet_header": [  # All in all this is 14 bytes of the packet received raw
                {
                    "dest_mac_addr": convert_byte_to_mac_string(ethernet_frame[0]),  # self.convert_byte_to_mac_string(mav_packet[:6]),
                    "source_mac_addr": convert_byte_to_mac_string(ethernet_frame[1]),  # self.convert_byte_to_mac_string(mav_packet[6:12]),
                    # after the 6th byte, and ends after counting 6 bytes [6: 6 + len(dest_mac_addr)]
                }
            ],
            "ip_header": [  # Standard at 20 bytes of the packet sent [len(ethernet_header): len(ethernet_header) + 20]
                {
                    "identification": mav_packet[18:20].hex(),  # 2 bytes starts from byte 14 + 20
                    "flags_and_fragment_offset": mav_packet[20:22].hex(),  # 1 byte [21:22]
                    "protocol": mav_packet[23:24].hex(),  # [23:24] 1 byte
                    "checksum": mav_packet[24:26].hex(),  # 2 bytes [24:26]
                    "source_ip": socket.inet_ntoa(mav_packet[26:30]),  # 4 bytes [26: 26 + 4]
                    "destination_ip": socket.inet_ntoa(mav_packet[30:34]),  # 4 bytes [30:30 + 4]
                }
            ],
            "udp_header": [  # Standard at 8 bytes of the packet sent mav_packet[34:42]
                {
                    "source_port": udp_frame[0],  # mav_packet[34:36],  # 2 bytes
                    "destination_port": udp_frame[1],  # mav_packet[36:38],  # 2 bytes
                    "length": udp_frame[2],  # mav_packet[38:40],  # 2 bytes
                    "checksum": mav_packet[40:42].hex(),  # 2 bytes
                }
            ],
            "udp_payload": [
                {
                    "payload_length": udp_payload_length,
                    "payload": udp_payload.hex()
                }
            ]
        }

    def stop_sniffing(self):
        self.stop_event.set()
        if self.sniffer:
            self.sniffer.close()

    def clean(self):
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
