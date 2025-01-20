from datetime import datetime
import json
from typing import List

from src.packets.packet import Packet
from src.session import Session


class GenericApi:
    @staticmethod
    def create_payload(packets: List[Packet]):
        payload = packets.copy()
        for packet in payload:
            packet.data = packet.data.hex().upper()
        return [
            {
                k: v
                for k, v in packet.__dict__.items()
                if k in Packet.__annotations__.keys()
            }
            for packet in payload
        ]

    @staticmethod
    def submit(session: Session):
        payload = GenericApi.create_payload(session.packets)
        with open(f"{datetime.now().strftime('%Y%m%d-%H%M%S')}.json", "w") as file:
            file.write(json.dumps(payload, indent=2))
