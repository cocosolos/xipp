from base64 import b64encode

from src.apis.generic import GenericApi
from src.packets.packet import Packet, PacketDirection


class PacketEaterPayload:
    def __init__(self, packet: Packet, name: str = ""):
        self.name: str = name
        self.zone_id: int = packet.zone_id
        self.version: str = "Unknown"
        self.timestamp: int = packet.capture_timestamp * 1000
        self.payload: str = b64encode(packet.data).decode("ascii")
        self.direction: PacketDirection = packet.direction
        self.origin: int = 4


class PacketEaterApi(GenericApi):
    def __init__(self):
        self.url = "http://localhost/submit"

    def create_payload(self, packet: Packet):
        return PacketEaterPayload(packet).__dict__
