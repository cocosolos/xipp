from src.packets.packet import Packet, PacketDirection


class IncomingPacket0x000A(Packet):
    def __init__(self, packet_data: bytes):
        super().__init__(PacketDirection.S2C, packet_data)
        self.timestamp = int.from_bytes(packet_data[0x38:0x3C], byteorder="little")
        self.zone_id = int.from_bytes(packet_data[0x30:0x34], byteorder="little")
        self.current_weather_id = int.from_bytes(
            packet_data[0x68:0x6A], byteorder="little"
        )
        self.previous_weather_id = int.from_bytes(
            packet_data[0x6A:0x6C], byteorder="little"
        )
        self.current_weather_start_tick = int.from_bytes(
            packet_data[0x6C:0x70], byteorder="little"
        )
        self.previous_weather_start_tick = int.from_bytes(
            packet_data[0x70:0x74], byteorder="little"
        )
        self.current_offset = int.from_bytes(packet_data[0x74:0x76], byteorder="little")
        self.previous_offset = int.from_bytes(
            packet_data[0x76:0x78], byteorder="little"
        )
