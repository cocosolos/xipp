# XI Packet Processor

Tool to gather data from captured FFXI packets and extract relevant information to send to API.

Accepts standard `full.log` files containing packets in the follow format:

```
[2024-10-08 00:00:00] Outgoing packet 0x000
        |  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      | 0123456789ABCDEF
    -----------------------------------------------------  ----------------------
      0 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    0 | ................

possible junk data

[2024-10-08 00:00:00] Incoming packet 0x000
```

As well as raw packet data as a hex string.

## Example Usage

```
python xipp.py --help
python xipp.py packetviewer full.log --send WeatherWatch
python xipp.py pv "C:\xi captures\" --recursive
```
