import time
import json


class PacketStorage:
    def __init__(self):
        self.mav_packets = list

    @staticmethod
    def store_packet(mav_packet):
        timestamp = time.time()
        file_name = f'{mav_packet["packet_id"]}.{timestamp}.json'
        file_path = f'storage/{file_name}'

        convert_to_json = json.dumps(mav_packet, indent=4)
        with open(file_path, 'w') as file:
            file.write(convert_to_json)
        return