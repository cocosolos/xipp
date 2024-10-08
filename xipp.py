from datetime import datetime
import math
import os
import re
import requests
import argparse

api_url = "http://127.0.0.1:3000/submit"

VANA_EPOCH = 1009810800
VANA_MINUTE = 2.4  # seconds
VANA_HOUR = 60 * VANA_MINUTE
VANA_DAY = 34 * VANA_HOUR
VANA_WEEK = 8 * VANA_DAY
VANA_MONTH = 30 * VANA_DAY
VANA_YEAR = 12 * VANA_MONTH

MAX_WEATHER_SECONDS = 6 * VANA_YEAR
MAX_WEATHER_TICK = MAX_WEATHER_SECONDS / VANA_MINUTE  # 3110400

# store data about the last encountered weather
last_weather = None


def estimate_cycle(timestamp, tick, prev=None):
    # 0x057 packet timestamp is local time so some comparison needs to be done against the tick to avoid miscalculation
    estimated_cycle = math.floor((timestamp - VANA_EPOCH) / MAX_WEATHER_SECONDS)
    # some zones never change weather, so we should only ever get 0x00A packets with accurate timestamps
    if prev is not None and prev == tick:
        return estimated_cycle
    calculated_tick = (timestamp - VANA_EPOCH) % MAX_WEATHER_SECONDS / VANA_MINUTE
    tick_difference = calculated_tick - tick

    # adjust the cycle if the tick difference is too large, this should catch any weirdness with timezones around the start/end of a cycle
    if abs(tick_difference) > MAX_WEATHER_TICK / 2:
        estimated_cycle += -1 if tick_difference > 0 else 1

    return estimated_cycle


def extract_timestamp(line):
    timestamp_pattern = r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]"
    match = re.search(timestamp_pattern, line)
    if match:
        timestamp_str = match.group(1)
        dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        unix_timestamp = int(dt.timestamp())
        return unix_timestamp
    else:
        return None


def extract_packet_data(packet_lines):
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


def parse_packet_00A(packet_lines, raw=False):
    global last_weather
    if not raw:
        packet_data = extract_packet_data(packet_lines)
    else:
        packet_data = packet_lines

    timestamp = int.from_bytes(packet_data[0x38:0x3C], byteorder="little")
    zoneId = int.from_bytes(packet_data[0x30:0x34], byteorder="little")
    weatherId1 = int.from_bytes(packet_data[0x68:0x6A], byteorder="little")
    weatherId2 = int.from_bytes(packet_data[0x6A:0x6C], byteorder="little")
    tick = int.from_bytes(packet_data[0x6C:0x70], byteorder="little")
    prev = int.from_bytes(packet_data[0x70:0x74], byteorder="little")
    offset1 = int.from_bytes(packet_data[0x74:0x76], byteorder="little")
    offset2 = int.from_bytes(packet_data[0x76:0x78], byteorder="little")
    cycle = estimate_cycle(timestamp, tick, prev)

    # build objects for current and previous weather
    packet1 = {
        "zoneId": zoneId,
        "cycle": cycle,
        "weatherId": weatherId1,
        "tick": tick,
        "prev": prev,
        "offset": offset1,
    }

    # store the data globally for 0x057 packets
    if not raw:
        last_weather = packet1

    # first tick in the cycle
    if prev > tick:
        cycle = cycle - 1

    packet2 = {
        "zoneId": zoneId,
        "cycle": cycle,
        "weatherId": weatherId2,
        "tick": prev,
        "offset": offset2,
    }

    return packet1, packet2


def parse_packet_057(packet_lines, raw=False, timestamp=None):
    global last_weather
    if not raw:
        packet_data = extract_packet_data(packet_lines)
        timestamp = extract_timestamp(packet_lines[0])
    else:
        packet_data = packet_lines

    if last_weather is None:
        # 0x057 doesn't include zone data, so skip if we don't have this from a previous 0x00A (zone in) packet
        return None

    tick = int.from_bytes(packet_data[0x04:0x08], byteorder="little")
    weatherId = int.from_bytes(packet_data[0x08:0x0A], byteorder="little")
    offset = int.from_bytes(packet_data[0x0A:0x0C], byteorder="little")
    cycle = estimate_cycle(timestamp, tick)

    # build object for current weather
    packet = {
        "zoneId": last_weather["zoneId"],
        "cycle": cycle,
        "tick": tick,
        "weatherId": weatherId,
        "offset": offset,
    }

    if "tick" in last_weather:
        packet["prev"] = last_weather["tick"]

    if not raw:
        last_weather = packet

    return packet


def send_to_api(json_data, api_url):
    response = requests.post(api_url, json=json_data)
    if response.status_code not in [200, 201]:
        return 0
    else:
        return 1


def process_log_file(file_path, api_url):
    global last_weather
    last_weather = None
    print(f"Processing file: {file_path}")
    with open(file_path, "r", errors="ignore") as file:
        lines = file.readlines()

    success = 0
    attempt = 0
    packet_lines = []
    current_packet_type = None

    # Sample incoming.log data:
    # [2024-10-08 00:00:00] Packet 0x000
    #         |  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      | 0123456789ABCDEF
    #     -----------------------------------------------------  ----------------------
    #       0 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    0 | ................
    #
    # possible junk data
    #
    # [2024-10-08 00:00:00] Packet 0x000

    for line in lines:
        if line == "\n":
            if current_packet_type and packet_lines:
                # process the previous packet
                if current_packet_type == "0x00A":
                    packet1, packet2 = parse_packet_00A(packet_lines)
                    attempt += 2
                    success += send_to_api(packet1, api_url)
                    success += send_to_api(packet2, api_url)
                elif current_packet_type == "0x057":
                    packet = parse_packet_057(packet_lines)
                    if packet:
                        attempt += 1
                        success += send_to_api(packet, api_url)
            # reset for the new packet
            packet_lines = []
            current_packet_type = None
            continue

        if re.match(r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]", line):
            # identify packet type
            if "0x00A" in line:
                current_packet_type = "0x00A"
            elif "0x057" in line:
                current_packet_type = "0x057"
            else:
                current_packet_type = None
        packet_lines.append(line)

    # process the last packet
    if packet_lines and current_packet_type == "0x00A":
        packet1, packet2 = parse_packet_00A(packet_lines)
        attempt += 2
        success += send_to_api(packet1, api_url)
        success += send_to_api(packet2, api_url)
    elif packet_lines and current_packet_type == "0x057":
        packet = parse_packet_057(packet_lines)
        if packet:
            attempt += 1
            success += send_to_api(packet, api_url)

    print(f"{success}/{attempt} weather records accepted.")
    return success, attempt


def process_directory(dir_path):
    total_success = 0
    total_attempt = 0

    for file in os.listdir(dir_path):
        if file == "incoming.log":
            file_path = os.path.join(dir_path, file)
            success, attempt = process_log_file(file_path, api_url)
            total_success += success
            total_attempt += attempt

    return total_success, total_attempt


def main():
    global last_weather

    try:
        parser = argparse.ArgumentParser(
            prog="XI Packet Processor",
            description="Processes FFXI 0x00A and 0x057 packets and sends weather information to WeatherWatchXI API.",
        )
        subparsers = parser.add_subparsers(
            help="commands", dest="command", required=True
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
            "-z",
            "--zone",
            action="store",
            type=int,
            help="Zone ID associated with packet (required for 0x057 packet).",
        )
        raw_data_parser.add_argument(
            "-t",
            "--timestamp",
            action="store",
            type=int,
            help="Unix timestamp packet was captured (required for 0x057 packet). Timezone doesn't matter.",
        )

        args = parser.parse_args()

        if args.command:
            if args.command in ["packetviewer", "pv"]:
                if not args.target:
                    print("You must provide a path to a file or directory to process.")
                    return
                for target in args.target:
                    total_success = 0
                    total_attempt = 0
                    target_path = os.path.abspath(target)
                    if os.path.isfile(target_path):
                        total_success, total_attempt = process_log_file(
                            target_path, api_url
                        )
                    elif os.path.isdir(target_path):
                        print(f"Processing directory: {target_path}")
                        success, attempt = process_directory(target_path)
                        if args.recursive:
                            for root, dirs, files in os.walk(target_path):
                                for dir in dirs:
                                    success, attempt = process_directory(
                                        os.path.join(root, dir)
                                    )
                                    total_success += success
                                    total_attempt += attempt
                    else:
                        print(f"File or directory not found: {target}")
                        return
                print(
                    f"Done processing. {total_success}/{total_attempt} total weather records accepted."
                )
            elif args.command in ["raw", "r"]:
                if not args.data:
                    print("You must provide packet data to process.")
                    return
                if args.data[0:2] == "0x":
                    args.data = args.data[2:]
                packet_data = bytes.fromhex(args.data)
                attempt = 0
                success = 0
                if packet_data[0] == 0x0A:
                    packet1, packet2 = parse_packet_00A(packet_data, True)
                    attempt += 2
                    success += send_to_api(packet1, api_url)
                    success += send_to_api(packet2, api_url)
                elif packet_data[0] == 0x57:
                    if not args.zone:
                        print(
                            "The zone option is required when processing raw 0x057 packets."
                        )
                        return
                    if not args.timestamp:
                        print(
                            "The timestamp option is required when processing raw 0x057 packets."
                        )
                        return
                    last_weather = {"zoneId": args.zone}
                    packet = parse_packet_057(packet_data, True, args.timestamp)
                    attempt += 1
                    success += send_to_api(packet, api_url)
                else:
                    print("Invalid packet.")
                    return
                print(f"{success}/{attempt} weather records accepted.")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
