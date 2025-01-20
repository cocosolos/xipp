import importlib
import os
import argparse
import zipfile

from src.apis.generic import GenericApi
from src.processor import Processor
from src.packets.packet import PacketDirection


def main():
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
            action="store",
            help="API to upload the processed packets to.",
        )
        # PacketViewer logs
        pv_data_parser = subparsers.add_parser(
            "packetviewer",
            aliases=["pv"],
            help="Process and send full.log file from PacketViewer.",
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
            help="Recursively search directories for full.log files to process.",
        )
        pv_data_parser.add_argument(
            "-s",
            "--send",
            action="store",
            help="API to upload the processed packets to.",
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
            type=str,
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
            action="store",
            help="API to upload the processed packets to.",
        )

        args = parser.parse_args()

        if args.send:
            current_dir = os.path.dirname(__file__)
            apis_dir = os.path.join(current_dir, "src/apis")
            apis_dir = os.path.normpath(apis_dir)
            for file_name in os.listdir(apis_dir):
                if file_name.startswith(args.send.lower()) and file_name.endswith(
                    ".py"
                ):
                    module_name = f"src.apis.{file_name[:-3]}"
                    module = importlib.import_module(module_name)
                    class_name = f"{args.send}Api"
                    try:
                        api_class = getattr(module, class_name)
                    except:
                        print("API not valid.")
                        return
                    api = api_class
                    break
        else:
            api = GenericApi
        processor = Processor(api)

        if args.command:
            if args.command in ["packetviewer", "pv"]:
                if not args.target:
                    print("You must provide a path to a file or directory to process.")
                    return
                for target in args.target:
                    target_path = os.path.abspath(target)
                    if zipfile.is_zipfile(target_path):
                        processor.process_archive(target_path)
                    elif os.path.isfile(target_path):
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
                print(f"Done processing capture logs.")
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
                processor.session.packets.append(packet)
                processor.api.submit(processor.session)
                print(f"Done processing packet.")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
