from datetime import time
import json
import os
import argparse

from src.apis.generic import GenericApi
from src.apis.packet_eater import PacketEaterApi
from src.processor import Processor
from src.packets.packet import PacketDirection


def main():
    api = PacketEaterApi()
    processor = Processor()

    try:
        parser = argparse.ArgumentParser(
            prog="XI Packet Processor",
            description="Processes captured FFXI network packets.",
        )
        subparsers = parser.add_subparsers(
            help="commands", dest="command", required=True
        )
        parser.add_argument(
            "-s",
            "--send",
            action="store_true",
            default=False,
            help="Upload the processed packets.",
        )
        parser.add_argument(
            "-u",
            "--url",
            action="store",
            help="URL to upload to.",
        )
        parser.add_argument(
            "-o",
            "--outfile",
            action="store",
            help="File to store output.",
        )
        # PacketViewer logs
        pv_data_parser = subparsers.add_parser(
            "packetviewer",
            aliases=["pv"],
            help="Process and send incoming.log file from PacketViewer.",
        )
        pv_data_parser.add_argument(
            "target",
            action="store",
            nargs="*",
            help="File or directory to process (accepts multiple).",
        )
        pv_data_parser.add_argument(
            "-r",
            "--recursive",
            default=False,
            action="store_true",
            help="Recursively search directories for incoming.log files to process.",
        )
        pv_data_parser.add_argument(
            "-s",
            "--send",
            action="store_true",
            default=False,
            help="Upload the processed packets.",
        )
        pv_data_parser.add_argument(
            "-u",
            "--url",
            action="store",
            help="URL to upload to.",
        )
        pv_data_parser.add_argument(
            "-o",
            "--outfile",
            action="store",
            help="File to store output.",
        )
        # TODO: add packet filter arg
        # Raw packets
        raw_data_parser = subparsers.add_parser(
            "raw", aliases=["r"], help="Process raw packet data."
        )
        raw_data_parser.add_argument(
            "data",
            action="store",
            help="Packet data as hex string.",
        )
        raw_data_parser.add_argument(
            "-d",
            "--direction",
            action="store",
            type=int,
            help="Packet direction (incoming/outgoing).",
        )
        raw_data_parser.add_argument(
            "-z",
            "--zone",
            action="store",
            type=int,
            help="Zone ID associated with packet.",
        )
        raw_data_parser.add_argument(
            "-t",
            "--timestamp",
            action="store",
            type=int,
            help="Unix timestamp packet was captured.",
        )
        raw_data_parser.add_argument(
            "-s",
            "--send",
            action="store_true",
            default=False,
            help="Upload the processed packets.",
        )
        raw_data_parser.add_argument(
            "-u",
            "--url",
            action="store",
            help="URL to upload to.",
        )
        raw_data_parser.add_argument(
            "-o",
            "--outfile",
            action="store",
            help="File to store output.",
        )

        args = parser.parse_args()

        if args.command:
            if args.command in ["packetviewer", "pv"]:
                if not args.target:
                    print("You must provide a path to a file or directory to process.")
                    return
                for target in args.target:
                    target_path = os.path.abspath(target)
                    if os.path.isfile(target_path):
                        processor.process_log_file(target_path)
                    elif os.path.isdir(target_path):
                        print(f"Processing directory: {target_path}")
                        processor.process_directory(target_path)
                        if args.recursive:
                            for root, dirs, _ in os.walk(target_path):
                                for dir in dirs:
                                    processor.process_directory(os.path.join(root, dir))
                    else:
                        print(f"File or directory not found: {target}")
                        return
                packets_parsed = 0
                for session in processor.sessions:
                    packets_parsed += len(session.packets)
                print(
                    f"Done processing {packets_parsed} packets from {len(processor.sessions)} capture logs."
                )
            elif args.command in ["raw", "r"]:
                if (
                    not args.direction
                    or not args.data
                    or not args.timestamp
                    or not args.zone
                ):
                    print(
                        "You must provide the packet direction, data, timestamp, and zone to process raw data."
                    )
                    return
                if args.data[0:2] == "0x":
                    args.data = args.data[2:]

                packet_data = bytes.fromhex(args.data)
                direction = PacketDirection.from_str(args.direction)
                packet = Processor.process_packet(
                    direction, packet_data, args.timestamp, args.zone
                )
                processor.current_session.packets.append(packet)
                processor.sessions.append(processor.current_session)

                print(f"Done processing packet.")

            if args.send or args.outfile:
                if not args.send or args.url:
                    api = GenericApi(args.url)
                for session in processor.sessions:
                    payload = api.create_payload(session.packets)
                    if args.send:
                        api.submit(payload)
                        time.sleep(
                            10
                        )  # TODO: this should only apply to PacketEater, and only until a "new session" command is available
                    if args.outfile:
                        with open(args.outfile, "a") as file:
                            file.write(json.dumps(payload, indent=2))

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
