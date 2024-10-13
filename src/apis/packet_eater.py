from base64 import b64encode
from typing import List

from src.apis.generic import GenericApi
from src.packets.packet import Packet, PacketDirection


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
    def __init__(self):
        self.url = "http://localhost/upload"

    def create_payload(self, packets: List[Packet]):
        payload_packets = [PacketEaterPacket(packet).__dict__ for packet in packets]
        return PacketEaterPayload(payload_packets).__dict__
