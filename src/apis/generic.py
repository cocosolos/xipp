import json
from typing import List
import requests

from src.packets.packet import Packet


class GenericApi:
    def __init__(self, url):
        self.url = url

    def create_payload(self, packets: List[Packet]):
        return [packet.data.hex() for packet in packets].__dict__

    def submit(self, payload: dict):
        response = requests.post(self.url, json=json.dumps(payload))
        if response.status_code not in [200, 201, 202]:
            return 0
        else:
            return 1
