import sys
import threading
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QVBoxLayout, QWidget
from src.packet_connection import PacketSniffer

NETWORK_INTERFACE = "wlan0"


class PacketSnifferGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.capture_thread = None
        self.capturing = False
        self.sniffer = None

    def initUI(self):
        self.setWindowTitle('Packet Sniffer')
        self.setGeometry(100, 100, 600, 400)

        self.start_button = QPushButton('Start Capture', self)
        self.start_button.clicked.connect(self.start_capture)

        self.stop_button = QPushButton('Stop Capture', self)
        self.stop_button.clicked.connect(self.stop_capture)

        self.log_output = QTextEdit(self)
        self.log_output.setReadOnly(True)

        layout = QVBoxLayout()
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.log_output)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def start_capture(self):
        if not self.capturing:
            self.capturing = True
            self.sniffer = PacketSniffer(NETWORK_INTERFACE, self.log_packet)
            self.capture_thread = threading.Thread(target=self.sniffer.start_sniffing)
            self.capture_thread.start()
            self.log_output.append('Capture started...')
            print('Capture started...')

    def stop_capture(self):
        if self.capturing:
            self.capturing = False
            self.sniffer.stop_sniffing()
            self.capture_thread.join(timeout=1)
            self.log_output.append('Capture stopped...')

    def log_packet(self, message):
        self.log_output.append(message)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PacketSnifferGUI()
    window.show()
    sys.exit(app.exec_())
