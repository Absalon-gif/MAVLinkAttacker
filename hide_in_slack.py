import subprocess
import math

EOF_MARKERS = [
        b'\x0A\x25\x25\x45\x4F\x46\x0A',
        b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A',
        b'\x0D\x25\x25\x45\x4F\x46\x0D',
        b'\x0D\x25\x25\x45\x4F\x46'
    ]


def get_physical_size(file_path):
    try:
        stat_output = subprocess.check_output(['stat', '--format=%s %b %B', file_path]).decode().strip()
        content_file_size, num_blocks, block_size = map(int, stat_output.split())
        physical_file_size = num_blocks * block_size
        return physical_file_size
    except Exception as e:
        print(f"Error retrieving physical size: {e}")
        return None


def check_database(data):
    for marker in EOF_MARKERS:
        index = data.find(marker)
        if index != -1:
            return index + len(marker)
    return -1


def extract_eof(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        eof_position = check_database(data)

        if eof_position == -1:
            print("EOF marker not found.")
            return None

        extracted_data = data[eof_position:]
        return extracted_data

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def calculate_shannon_entropy(data):
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


def flag_abnormal_files(data):
        slack_data_entropy = calculate_shannon_entropy(data)
        return slack_data_entropy

def print_statements(entropy, file_path, low_threshold=1.0):
    print(f"Entropy of extracted data: {entropy}")
    print(f"File: {file_path}, Entropy: {entropy}")

    if 0.2 < entropy < low_threshold:
        print(f"Flagged: {file_path}; Has low entropy, however still suspicious")
    elif entropy > low_threshold:
        print(f"Flagged: {file_path}; Has high entropy, likely altered")
    elif entropy <= 0.2:
        print(f"Normal: {file_path}; File seems normal")


if __name__ == "__main__":
    input_file = input("Enter the path to the file: ")

    physical_size = get_physical_size(input_file)
    if physical_size is not None:
        print(f"Physical Size: {physical_size} bytes")

        padded_data = extract_eof(input_file)

        if padded_data is not None:
            data_entropy = flag_abnormal_files(padded_data)
            print_statements(data_entropy, input_file)

    else:
        print("Could not retrieve physical size. Please check the file path.")
