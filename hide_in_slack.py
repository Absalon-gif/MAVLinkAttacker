from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QLabel, QVBoxLayout, QFileDialog, QTextEdit
import subprocess
import sys
import math

EOF_MARKERS = [
        b'\x0A\x25\x25\x45\x4F\x46\x0A',
        b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A',
        b'\x0D\x25\x25\x45\x4F\x46\x0D',
        b'\x0D\x25\x25\x45\x4F\x46'
    ]


class EntropyAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Entropy Analyzer')

        self.layout = QVBoxLayout()

        self.label = QLabel('Select a file to analyze:')
        self.layout.addWidget(self.label)

        self.text_edit = QTextEdit()
        self.layout.addWidget(self.text_edit)

        self.button = QPushButton('Open File')
        self.button.clicked.connect(self.open_file)
        self.layout.addWidget(self.button)

        self.setLayout(self.layout)

    def open_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a file", "", "All Files (*)", options=options)

        if file_path:
            self.analyze_file(file_path)

    def analyze_file(self, file_path):
        physical_file_size = self.get_physical_size(file_path)
        self.text_edit.append(
            f"Physical Size: {physical_file_size} bytes" if physical_file_size else "Could not retrieve physical size.")

        extracted_data = self.extract_eof(file_path)

        if extracted_data:
            data_entropy = self.calculate_entropy(extracted_data)
            self.text_edit.append(f"Entropy of extracted data: {data_entropy}")
            self.flag_abnormal_files(data_entropy)

    @staticmethod
    def get_physical_size(file_path):
        try:
            command = subprocess.check_output(['stat', '--format=%s %b %B', file_path]).decode().strip()
            content_file_size, num_blocks, block_size = map(int, command.split())
            return num_blocks * block_size
        except Exception as e:
            print(f"Error retrieving physical size: {e}")
            return None

    def extract_eof(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            eof_position = self.check_database(data)

            if eof_position == -1:
                print("EOF marker not found.")
                return None

            return data[eof_position:]

        except Exception as e:
            print(f"An error occurred: {e}")
            return None

    @staticmethod
    def check_database(data):
        for marker in EOF_MARKERS:
            index = data.find(marker)
            if index != -1:
                return index + len(marker)
        return -1

    @staticmethod
    def calculate_entropy(data):
        if not data:
            return 0

        byte_frequency = {}
        for byte in data:
            byte_frequency[byte] = byte_frequency.get(byte, 0) + 1

        entropy = 0.0
        length = len(data)

        for freq in byte_frequency.values():
            p = freq / length
            entropy -= p * math.log2(p)

        return entropy

    def flag_abnormal_files(self, entropy, low_threshold=1.0):
        if 0.2 < entropy < low_threshold:
            self.text_edit.append("Flagged: Low entropy, but still suspicious.")
        elif entropy > low_threshold:
            self.text_edit.append("Flagged: High entropy, likely altered.")
        elif entropy <= 0.2:
            self.text_edit.append("Normal: File seems normal.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    analyzer = EntropyAnalyzer()
    analyzer.resize(400, 300)
    analyzer.show()
    sys.exit(app.exec_())




