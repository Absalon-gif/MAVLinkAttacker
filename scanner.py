import sys
import threading
from PyQt5.QtCore import QThread, pyqtSignal
from src.attack_spectrum.attack import Attacker
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QPushButton, QLineEdit, QTextEdit, QWidget, QHBoxLayout

NETWORK_INTERFACE = 'wlan0'


class ARPScan(QThread):
    update_log = pyqtSignal(str)

    def __init__(self, start_ip, end_ip, attacker):
        super().__init__()
        self.start_ip = start_ip
        self.end_ip = end_ip
        self.attacker = attacker

    def run(self):
        active_hosts = self.attacker.start_scan(self.start_ip, self.end_ip)
        print(f"active hosts: {active_hosts}")
        self.update_log.emit("Active hosts found:")
        for ip, mac in active_hosts:
            self.update_log.emit(f"IP: {ip}, MAC: {mac}")


class ScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.attacker = Attacker(NETWORK_INTERFACE)
        self.scan_thread = None
        self.mitm_thread = None
        self.packet_forwarder = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ARP Scan Tool')
        self.setGeometry(100, 100, 600, 600)

        # Input fields
        self.start_ip_input = QLineEdit(self)
        self.start_ip_input.setPlaceholderText('Start IP (e.g., 192.168.1.1)')
        self.end_ip_input = QLineEdit(self)
        self.end_ip_input.setPlaceholderText('End IP (e.g., 192.168.1.20)')

        self.drone_ip_input = QLineEdit(self)
        self.drone_ip_input.setPlaceholderText('Drone IP (e.g., 192.168.1.1)')
        self.drone_mac_input = QLineEdit(self)
        self.drone_mac_input.setPlaceholderText('Drone MAC (e.g., 66:77:88:99:AA:BB)')
        self.gcs_ip_input = QLineEdit(self)
        self.gcs_ip_input.setPlaceholderText('GCS IP (e.g., 192.168.1.2)')
        self.gcs_mac_input = QLineEdit(self)
        self.gcs_mac_input.setPlaceholderText('GCS MAC (e.g., CC:DD:EE:FF:00:11)')

        # Buttons
        self.start_scan_button = QPushButton('Start Scan', self)
        self.start_mitm_button = QPushButton('Perform MITM Attack', self)

        # Log output
        self.log_output = QTextEdit(self)
        self.log_output.setReadOnly(True)

        self.start_scan_button.clicked.connect(self.start_scan)
        self.start_mitm_button.clicked.connect(self.perform_mitm_attack)

        # Scan Layout
        scan_layout = QHBoxLayout()
        scan_layout.addWidget(QLabel('Start IP:'))
        scan_layout.addWidget(self.start_ip_input)
        scan_layout.addWidget(QLabel('End IP:'))
        scan_layout.addWidget(self.end_ip_input)

        # MITM Layout
        mitm_layout = QVBoxLayout()
        mitm_layout.addWidget(QLabel('Drone IP:'))
        mitm_layout.addWidget(self.drone_ip_input)
        mitm_layout.addWidget(QLabel('Drone MAC:'))
        mitm_layout.addWidget(self.drone_mac_input)
        mitm_layout.addWidget(QLabel('GCS IP:'))
        mitm_layout.addWidget(self.gcs_ip_input)
        mitm_layout.addWidget(QLabel('GCS MAC:'))
        mitm_layout.addWidget(self.gcs_mac_input)

        button_layout = QVBoxLayout()
        button_layout.addWidget(self.start_scan_button)
        button_layout.addWidget(self.start_mitm_button)

        layout = QVBoxLayout()
        layout.addLayout(scan_layout)
        layout.addLayout(mitm_layout)
        layout.addLayout(button_layout)
        layout.addWidget(self.log_output)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.show()

    def start_threads(self, attacker_mac, drone_ip, drone_mac, gcs_ip, gcs_mac):
        if self.mitm_thread is None or self.mitm_thread.is_alive():
            self.mitm_thread = threading.Thread(target=self.attacker.start_arp_spoof,
                                                args=(attacker_mac, drone_ip, drone_mac, gcs_ip, gcs_mac))
        if self.packet_forwarder is None or self.packet_forwarder.is_alive():
            self.packet_forwarder = threading.Thread(target=self.attacker.start_packet_forwarder)

        self.mitm_thread.start()
        self.packet_forwarder.start()
        try:
            self.mitm_thread.join()
            self.packet_forwarder.join()
        except KeyboardInterrupt:
            print("stopping packet forwarder and mitm")

    def perform_mitm_attack(self):
        attacker_mac = '80:af:ca:28:ae:1d'
        drone_ip = self.drone_ip_input.text()
        drone_mac = self.drone_mac_input.text()
        gcs_ip = self.gcs_ip_input.text()
        gcs_mac = self.gcs_mac_input.text()

        if not (attacker_mac and drone_ip and drone_mac and gcs_ip and gcs_mac):
            self.log_output.append('Enter all necessary fields for MITM attack.')
            return

        self.start_threads(attacker_mac, drone_ip, drone_mac, gcs_ip, gcs_mac)
        self.log_output.append('Starting MITM attack...')

        self.log_output.append('MITM attack in progress...')

    def start_scan(self):
        start_ip = self.start_ip_input.text()
        end_ip = self.end_ip_input.text()
        if not start_ip or not end_ip:
            self.log_output.append(f'Enter range of IP scan')
            return

        self.log_output.clear()
        self.scan_thread = ARPScan(start_ip, end_ip, self.attacker)
        self.scan_thread.update_log.connect(self.log_output.append)
        self.scan_thread.start()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    scanner = ScannerApp()
    sys.exit(app.exec_())
