from datetime import datetime, timezone
import importlib
import io
import os
import unittest
from unittest import mock

from src.packets.packet import Packet, PacketDirection
from src.processor import Processor


class TestProcessor(unittest.TestCase):
    def setUp(self):
        self.processor = Processor()
        self.timestamp_dt = datetime.now(timezone.utc)
        self.timestamp_str = self.timestamp_dt.strftime("%Y-%m-%d %H:%M:%S")
        self.timestamp_int = int(self.timestamp_dt.timestamp())
        self.outgoing_packet_line = f"[{self.timestamp_str}] Outgoing packet 0x000:"
        self.incoming_packet_line = f"[{self.timestamp_str}] Incoming packet 0x000:"
        self.packet_lines = [
            "        |  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      | 0123456789ABCDEF",
            "    -----------------------------------------------------  ----------------------",
            "      0 | 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF    0 | ................",
            "      1 | 00 11 22 33 -- -- -- -- -- -- -- -- -- -- -- --    1 | ................",
        ]
        self.packet_bytes = bytes.fromhex("00112233445566778899AABBCCDDEEFF00112233")
        self.packet_classes = self._get_packet_classes()

    def _get_packet_classes(self):
        packet_classes = []
        current_dir = os.path.dirname(__file__)

        incoming_packets_dir = os.path.join(current_dir, "../src/packets/incoming")
        incoming_packets_dir = os.path.normpath(incoming_packets_dir)
        for file_name in os.listdir(incoming_packets_dir):
            if file_name.startswith("IncomingPacket") and file_name.endswith(".py"):
                packet_type_str = file_name[-7:-3]
                packet_type = int(packet_type_str, 16)
                module_name = f"src.packets.incoming.{file_name[:-3]}"
                module = importlib.import_module(module_name)
                class_name = f"IncomingPacket0x{packet_type_str}"
                packet_class = getattr(module, class_name)
                packet_classes.append((PacketDirection.S2C, packet_class, packet_type))

        outgoing_packets_dir = os.path.join(current_dir, "../src/packets/outgoing")
        outgoing_packets_dir = os.path.normpath(outgoing_packets_dir)
        for file_name in os.listdir(outgoing_packets_dir):
            if file_name.startswith("OutgoingPacket") and file_name.endswith(".py"):
                packet_type_str = file_name[-7:-3]
                packet_type = int(packet_type_str, 16)
                module_name = f"src.packets.outgoing.{file_name[:-3]}"
                module = importlib.import_module(module_name)
                class_name = f"OutgoingPacket0x{packet_type_str}"
                packet_class = getattr(module, class_name)
                packet_classes.append((PacketDirection.C2S, packet_class, packet_type))

        return packet_classes

    def test_create_packet(self):
        for packet_direction, packet_class, packet_type in self.packet_classes:
            with self.subTest(packet_class=packet_class, packet_type=packet_type):
                packet_data = (
                    packet_type.to_bytes(2, byteorder="little") + self.packet_bytes
                )
                packet = Processor.create_packet(packet_direction, packet_data)
                self.assertIsInstance(packet, packet_class)
        packet = Processor.create_packet(PacketDirection.S2C, self.packet_bytes)
        self.assertIsInstance(packet, Packet)
        packet = Processor.create_packet(PacketDirection.C2S, self.packet_bytes)
        self.assertIsInstance(packet, Packet)

    def test_process_log_file(self):
        # TODO: test backfilling zone data
        outgoing_packet = [self.outgoing_packet_line] + self.packet_lines
        incoming_packet = [self.incoming_packet_line] + self.packet_lines
        junk_data = ["\n", "junk data", "\n"]
        log_file = "\n".join(outgoing_packet + junk_data + incoming_packet)
        log_file = io.StringIO(log_file)
        with mock.patch("src.processor.open", return_value=log_file, create=True):
            self.processor.process_log_file(log_file)
        self.assertEqual(len(self.processor.sessions), 1)
        self.assertEqual(len(self.processor.sessions[0].packets), 2)

    @mock.patch("src.processor.os.listdir")
    @mock.patch(
        "src.processor.os.path.join",
        side_effect=lambda dir_path, file: f"{dir_path}/{file}",
    )
    @mock.patch.object(Processor, "process_log_file")
    def test_process_directory(self, mock_process_log_file, _, mock_listdir):
        mock_listdir.return_value = ["full.log", "incoming.log", "outgoing.log"]

        self.processor.process_directory("/mock/directory")

        mock_listdir.assert_called_once_with("/mock/directory")
        mock_process_log_file.assert_called_once_with(
            self.processor, "/mock/directory/full.log"
        )

    def test_process_packet(self):
        packet = Processor.process_packet(
            PacketDirection.S2C, self.packet_bytes, 12345, 67890
        )
        self.assertIsInstance(packet, Packet)
        self.assertEqual(
            packet.capture_timestamp,
            12345,
        )
        self.assertEqual(
            packet.zone_id,
            67890,
        )

    def test_extract_timestamp(self):
        result = Processor.extract_timestamp(self.incoming_packet_line)
        self.assertEqual(result, self.timestamp_int)

    def test_extract_packet_data(self):
        test_packet = [self.incoming_packet_line] + self.packet_lines
        result = Processor.extract_packet_data(test_packet)
        self.assertEqual(
            result,
            self.packet_bytes,
        )


if __name__ == "__main__":
    unittest.main()
