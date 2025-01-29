# ys-sniffer

A high-level, embeddable packet sniffer for anime game, written in Rust.

## About

The library attempts to _guess_ which packet acts as the 'handshake' for encryption between the client and server.

As such, it will be able to decrypt future packets, but it still does not identify them by **name**.

## Features

- `processor` - Exposes the packet processor, allowing for low-level packet input.

## See Other

- [ayylmao](https://github.com/Magix-Archive/GC-Universe) - Modern packet sniffer (unfinished)
- [evergreen](https://github.com/TheLostTree/evergreen) - Original Rust/WinPcap packet sniffer

---

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.