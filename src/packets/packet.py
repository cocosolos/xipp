from enum import Enum


class PacketDirection(int, Enum):
    S2C = 0
    C2S = 1

    @staticmethod
    def from_str(label: str):
        if label.upper() in ("S2C", "SERVER_TO_CLIENT", "INCOMING"):
            return PacketDirection.S2C
        elif label.upper() in ("C2S", "CLIENT_TO_SERVER", "OUTGOING"):
            return PacketDirection.C2S


class Packet:
    def __init__(self, direction: PacketDirection, packet_data: bytes):
        self.type: int = (
            int.from_bytes(packet_data[0x00:0x02], byteorder="little") & ~0xFE00
        )
        self.size: int = (
            int.from_bytes(packet_data[0x01:0x02], byteorder="little") & ~0x80
        )
        self.sync: int = int.from_bytes(packet_data[0x02:0x04], byteorder="little")
        self.data: bytes = packet_data
        self.direction: PacketDirection = direction
        self.zone_id: int = None
        self.capture_timestamp: int = None
