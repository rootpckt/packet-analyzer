# packet-analyzer

A low-level network packet analyzer written in C/C++ that captures and decodes raw packets for learning networking and systems programming.

## Features
- Clean C/C++ project structure
- Single entry point (`main.cpp`)
- Modular logic in `library.cpp`
- Designed for raw packet inspection (Ethernet/IP/TCP/UDP in future)

## Build

```bash
g++ src/main.cpp src/library.cpp -Iinclude -o analyzer
