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
    capture_timestamp: int
    direction: PacketDirection
    type: int
    size: int
    sync: int
    zone_id: int
    data: bytes

    def __init__(self, direction: PacketDirection, packet_data: bytes):
        self.capture_timestamp = None
        self.direction = direction
        self.type = int.from_bytes(packet_data[0x00:0x02], byteorder="little") & ~0xFE00
        self.size = int.from_bytes(packet_data[0x01:0x02], byteorder="little") & ~0x80
        self.sync = int.from_bytes(packet_data[0x02:0x04], byteorder="little")
        self.zone_id = None
        self.data = packet_data
