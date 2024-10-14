import os

def calculate_slack_space(logical_size, block_size=4096):
    physical_file_size = (logical_size + block_size - 1) // block_size * block_size
    slack_space_size = physical_file_size - logical_size
    return slack_space_size, physical_file_size


def hide_data_in_slack_space(target_file, hidden_file):
    logical_file_size = os.path.getsize(target_file)

    slack_space_size, physical_size = calculate_slack_space(logical_file_size)
    print(f"Slack space available: {slack_space_size} bytes")

    with open(hidden_file, 'rb') as f:
        hidden_data = f.read()

    if len(hidden_data) > slack_space_size:
        raise Exception("Hidden data does not fit in slack space.")

    with open(target_file, 'r+b') as f:
        eof_tail = logical_file_size

        f.seek(eof_tail)

        f.write(hidden_data)


if __name__ == "__main__":
    target_file = '/mnt/ntfs_usb/maybe4.pdf'
    hidden_file = '/mnt/ntfs_usb/cat-3266673_640_11zon.jpg'

    hide_data_in_slack_space(target_file, hidden_file)
    print("Hidden file data has been successfully hidden!")
