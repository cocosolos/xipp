import os
import re
import requests
from datetime import datetime, timezone
from typing import List

from src.session import Session
from src.packets.packet import Packet, PacketDirection
from src.packets.incoming.IncomingPacket0x000A import IncomingPacket0x000A
from src.packets.incoming.IncomingPacket0x000E import IncomingPacket0x000E
from src.packets.incoming.IncomingPacket0x0057 import IncomingPacket0x0057


class Processor:
    def __init__(self):
        self.current_session: Session = Session()
        self.sessions: List[Session] = []

    def process_log_file(self, file_path: str | os.PathLike):
        print(f"Processing file: {file_path}")
        with open(file_path, "r", errors="ignore") as file:
            lines = file.readlines()

        packet_lines = []
        reading_packet = False

        for line in lines:
            if line == "\n":
                if reading_packet and packet_lines:
                    packet_direction = PacketDirection.from_str(
                        packet_lines[0].split(" ")[2]
                    )
                    packet_data = Processor.extract_packet_data(packet_lines)
                    packet_timestamp = Processor.extract_timestamp(packet_lines[0])
                    packet = Processor.process_packet(
                        packet_direction,
                        packet_data,
                        packet_timestamp,
                        self.current_session.zone_id,
                    )
                    self.current_session.zone_id = packet.zone_id
                    if packet.zone_id and packet.type != 0x000A:
                        for previous_packet in reversed(self.current_session.packets):
                            if not previous_packet.zone_id:
                                previous_packet.zone_id = packet.zone_id
                            else:
                                break
                    self.current_session.packets.append(packet)
                packet_lines = []
                reading_packet = False
                continue

            if re.match(r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]", line):
                reading_packet = True
            packet_lines.append(line)

        # process the last packet
        if reading_packet and packet_lines:
            packet_direction = PacketDirection.from_str(packet_lines[0].split(" ")[2])
            packet_data = Processor.extract_packet_data(packet_lines)
            packet_timestamp = Processor.extract_timestamp(packet_lines[0])
            packet = self.process_packet(
                packet_direction,
                packet_data,
                packet_timestamp,
                self.current_session.zone_id,
            )
            self.current_session.zone_id = packet.zone_id
            if packet.zone_id and packet.type != 0x000A:
                for previous_packet in reversed(self.current_session.packets):
                    if not previous_packet.zone_id:
                        previous_packet.zone_id = packet.zone_id
                    else:
                        break
            self.current_session.packets.append(packet)
        self.sessions.append(self.current_session)
        self.current_session = Session()

    def process_directory(self, dir_path: str | os.PathLike):
        for file in os.listdir(dir_path):
            if file == "full.log":
                file_path = os.path.join(dir_path, file)
                self.process_log_file(self, file_path)

    @staticmethod
    def process_packet(
        direction: PacketDirection,
        packet_data: bytes,
        timestamp: int,
        zone_id: int,
    ):
        packet = Processor.create_packet(direction, packet_data)
        packet.capture_timestamp = timestamp
        if not packet.zone_id:
            packet.zone_id = zone_id
        return packet

    @staticmethod
    def create_packet(direction: PacketDirection, packet_data: bytes):
        packet_type = (
            int.from_bytes(packet_data[0x00:0x02], byteorder="little") & ~0xFE00
        )

        match (direction, packet_type):
            case (PacketDirection.S2C, 0x000A):
                return IncomingPacket0x000A(packet_data)
            case (PacketDirection.S2C, 0x000E):
                return IncomingPacket0x000E(packet_data)
            case (PacketDirection.S2C, 0x0057):
                return IncomingPacket0x0057(packet_data)

        return Packet(direction, packet_data)

    @staticmethod
    def extract_timestamp(line: str):
        timestamp_pattern = r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]"
        match = re.search(timestamp_pattern, line)
        if match:
            timestamp_str = match.group(1)
            dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            dt_utc = dt.replace(tzinfo=timezone.utc)
            unix_timestamp = int(dt_utc.timestamp())
            return unix_timestamp
        else:
            return None

    @staticmethod
    def extract_packet_data(packet_lines: List[str]):
        packet_data = []

        for line in packet_lines:
            # skip lines that don't contain packet data
            if "|" not in line or line.split("|")[0].strip() == "":
                continue
            # extract the packet data, removing line numbers and trailing junk
            data_part = line.split("|")[1].strip().split()[0:16]
            packet_data.extend(hex for hex in data_part if hex != "--")

        packet_data = bytes.fromhex("".join(packet_data))

        return packet_data
