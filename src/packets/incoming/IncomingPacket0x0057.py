from src.packets.packet import Packet, PacketDirection


class IncomingPacket0x0057(Packet):
    def __init__(self, packet_data: bytes):
        super().__init__(PacketDirection.S2C, packet_data)
        self.weather_start_tick = int.from_bytes(
            packet_data[0x04:0x08], byteorder="little"
        )
        self.weather_id = int.from_bytes(packet_data[0x08:0x0A], byteorder="little")
        self.offset = int.from_bytes(packet_data[0x0A:0x0C], byteorder="little")
