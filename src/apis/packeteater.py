from base64 import b64encode
import json
from typing import List

import requests

from src.apis.generic import GenericApi
from src.packets.packet import Packet, PacketDirection
from src.session import Session


class PacketEaterPacket:
    def __init__(self, packet: Packet):
        self.zone_id: int = packet.zone_id
        self.timestamp: int = packet.capture_timestamp * 1000
        self.payload: str = b64encode(packet.data).decode("ascii")
        self.direction: PacketDirection = packet.direction


class PacketEaterPayload:
    def __init__(self, packets: List[PacketEaterPacket]):
        self.origin: int = 4
        self.packets = packets


class PacketEaterApi(GenericApi):
    url = "http://localhost/upload"

    @staticmethod
    def create_payload(packets: List[Packet]):
        payload_packets = [PacketEaterPacket(packet).__dict__ for packet in packets]
        return PacketEaterPayload(payload_packets).__dict__

    @staticmethod
    def submit(session: Session):
        payload = PacketEaterApi.create_payload(session.packets)
        for packet in payload:
            response = requests.post(
                PacketEaterApi.url, json=json.dumps(packet), timeout=5
            )
            if response.status_code not in [200, 201, 202]:
                return 0
        return 1
