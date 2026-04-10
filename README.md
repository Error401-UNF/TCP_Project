


# Environment Specifications

The program was developed and tested in a reproducible NixOS environment.

- Operating System: NixOS 25.11 (Xantusia) x86_64

- Linux Kernel: 6.19.11

- Python Version: 3.13.12

- Hardware Platform: AMD Ryzen 7 7840HS (x86_64)

- Dependencies: - Standard Python 3.x library (socket, struct, threading, time)

  - numpy (as provided by the Nix flake environment)

  - stdenv.cc.cc.lib and zlib (linked via LD_LIBRARY_PATH)

# Assumptions & Design Choices

1. Atomic File Transfer: It is assumed that each send() and recv() call handles exactly one complete file/message. The receiver waits for an EOF marker (SYN_FLAG) before releasing the data to the application layer.

2. Owner Logging: All transport layer logs are prefixed with TCP {owner} (e.g., "Initiator" or "Listener") to facilitate debugging in multi-threaded environments.

3. Buffer Discipline: The system strictly enforces MAX_NETWORK_BUFFER. If the combined size of the in-order buffer and the out-of-order "future" packets exceeds this limit, incoming packets are dropped.

# Usage

Execution

The transport logic is designed to be imported as a module:

```py
from transport import TransportSocket

# For a Listener (Server)
sock = TransportSocket()
sock.socket("TCP_LISTENER", 8080)

# For an Initiator (Client)
sock = TransportSocket()
sock.socket("TCP_INITIATOR", 8080, server_ip="127.0.0.1")
```

**Nix Shell (Optional)**

If using Nix, you can enter the development environment using the provided flake.nix:
```sh
nix develop
```

