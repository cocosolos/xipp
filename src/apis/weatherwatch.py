import math
from typing import List

import requests

from src.apis.generic import GenericApi
from src.packets.incoming.IncomingPacket0x000A import IncomingPacket0x000A
from src.packets.incoming.IncomingPacket0x0057 import IncomingPacket0x0057
from src.packets.packet import Packet
from src.session import Session


VANA_EPOCH = 1009810800
VANA_MINUTE = 2.4  # seconds
VANA_HOUR = 60 * VANA_MINUTE
VANA_DAY = 24 * VANA_HOUR
VANA_WEEK = 8 * VANA_DAY
VANA_MONTH = 30 * VANA_DAY
VANA_YEAR = 12 * VANA_MONTH
WEATHER_CYCLE_LENGTH = 6 * VANA_YEAR + math.pi / 10


def estimate_cycle(timestamp, tick, prev=None):
    # 0x057 packet timestamp is local time so some comparison needs to be done against the tick to avoid miscalculation
    estimated_cycle = math.floor((timestamp - VANA_EPOCH) / WEATHER_CYCLE_LENGTH)
    # some zones never change weather, so we should only ever get 0x00A packets with accurate timestamps
    if prev is not None and prev == tick:
        return estimated_cycle
    last_cycle_start = math.floor(VANA_EPOCH + estimated_cycle * WEATHER_CYCLE_LENGTH)
    calculated_tick = math.floor((timestamp - last_cycle_start) / VANA_MINUTE)
    tick_difference = calculated_tick - tick
    # adjust the cycle if the tick difference is too large, this should catch any weirdness with timezones around the start/end of a cycle
    if abs(tick_difference) > WEATHER_CYCLE_LENGTH / 2.4 / 2:
        estimated_cycle += -1 if tick_difference > 0 else 1
    return estimated_cycle


class WeatherWatchApi(GenericApi):
    url = "https://weather.solos.dev/submit"
    version = "0.0.1"

    @staticmethod
    def create_payload(packets: List[Packet]):
        payload_packets = []
        for packet in packets:
            if isinstance(packet, IncomingPacket0x000A):
                cycle = estimate_cycle(
                    packet.timestamp,
                    packet.current_weather_start_tick,
                    packet.previous_weather_start_tick,
                )
                payload_packets.append(
                    {
                        "zoneId": packet.zone_id,
                        "cycle": cycle,
                        "weatherId": packet.current_weather_id,
                        "tick": packet.current_weather_start_tick,
                        "offset": packet.current_offset,
                        "prev": packet.previous_weather_start_tick,
                    }
                )
                if (
                    packet.previous_weather_start_tick
                    > packet.current_weather_start_tick
                ):
                    cycle -= 1
                payload_packets.append(
                    {
                        "zoneId": packet.zone_id,
                        "cycle": cycle,
                        "weatherId": packet.previous_weather_id,
                        "tick": packet.previous_weather_start_tick,
                        "offset": packet.previous_offset,
                    }
                )
            elif isinstance(packet, IncomingPacket0x0057):
                cycle = estimate_cycle(
                    packet.capture_timestamp, packet.weather_start_tick
                )
                payload_packets.append(
                    {
                        "zoneId": packet.zone_id,
                        "cycle": cycle,
                        "weatherId": packet.weather_id,
                        "tick": packet.weather_start_tick,
                        "offset": packet.offset,
                    }
                )
        return payload_packets

    @staticmethod
    def submit(session: Session):
        headers = {"User-Agent": f"xipp/{WeatherWatchApi.version}"}
        payload = WeatherWatchApi.create_payload(session.packets)
        for packet in payload:
            response = requests.post(
                WeatherWatchApi.url, json=packet, timeout=5, headers=headers
            )
            if response.status_code not in [200, 201, 202]:
                print(response.text)
                return 0
        return 1
