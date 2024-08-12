import socket
import binascii
import ipaddress


def create_arp_request(src_mac, src_ip, dest_ip):
    from .attack import Attacker
    dest_mac = 'ff:ff:ff:ff:ff:ff'  # Broadcast MAC
    target_mac = '00:00:00:00:00:00'
    ethernet_frame = Attacker.create_ethernet_packet(dest_mac, src_mac)
    arp_request = Attacker.create_arp_packet(src_mac, src_ip, target_mac, dest_ip, 1)
    return ethernet_frame + arp_request


def parse_arp_reply(packet):
    arp_header = packet[14:42]
    sender_mac = arp_header[8:14]
    sender_ip = socket.inet_ntoa(arp_header[14:18])

    return sender_ip, ':'.join(f'{b:02x}' for b in sender_mac)


def scan_ip(interface, src_ip, ip):
    src_mac = '80:af:ca:28:ae:1d'
    arp_request = create_arp_request(src_mac, src_ip, ip)

    scanner = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    scanner.bind((interface, 0))
    scanner.send(arp_request)

    try:
        arp_reply, _ = scanner.recvfrom(65535)
        if arp_reply:
            sender_ip, sender_mac = parse_arp_reply(arp_reply)
            return sender_ip, sender_mac
    except socket.timeout:
        return None

    return None


def scan_range(interface, start_ip, end_ip):
    active_hosts = []

    start_ip_int = int(ipaddress.ip_address(start_ip))
    end_ip_int = int(ipaddress.ip_address(end_ip))

    for ip_int in range(start_ip_int, end_ip_int + 1):
        ip = str(ipaddress.ip_address(ip_int))
        print(f"Scanning IP: {ip}")
        host = scan_ip(interface, start_ip, ip)
        if host:
            if host[0] == '0.0.0.0':
                continue
            else:
                active_hosts.append(host)

    return active_hosts
