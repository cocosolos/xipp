from src.packets.packet import Packet, PacketDirection


class IncomingPacket0x000E(Packet):
    def __init__(self, packet_data: bytes):
        super().__init__(PacketDirection.S2C, packet_data)
        self.npc_id = int.from_bytes(packet_data[0x04:0x08], byteorder="little")
        self.zone_id = (self.npc_id >> 12) & 0x0FFF
