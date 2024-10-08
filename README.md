# XI Packet Processor

Tool to gather data from captured FFXI packets and extract relevant information to send to API.

Currently handles the [0x0057](https://github.com/atom0s/XiPackets/tree/main/world/server/0x0057) and [0x000A](https://github.com/atom0s/XiPackets/tree/main/world/server/0x000A) packets.

Accepts standard `incoming.log` files containing packets in the follow format:

```
[2024-10-08 00:00:00] Packet 0x000
        |  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      | 0123456789ABCDEF
    -----------------------------------------------------  ----------------------
      0 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    0 | ................

possible junk data

[2024-10-08 00:00:00] Packet 0x000
```

As well as raw packet data as a hex string.

## Example Usage

```
python xipp.py --help
python xipp.py packetviewer incoming.log
python xipp.py pv "C:\xi captures\" --recursive
python xipp.py raw 57063100C3002C0003001000 --zone 239 --timestamp 1576654297
```
