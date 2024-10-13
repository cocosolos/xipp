from typing import List

from src.packets.packet import Packet


class Session:
    def __init__(self):
        self.name: str = None
        self.zone_id: int = None
        self.packets: List[Packet] = []
