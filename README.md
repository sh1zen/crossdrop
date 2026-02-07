# Sendme

This is an example application using [iroh](https://crates.io/crates/iroh) with
the [iroh-blobs](https://crates.io/crates/iroh-blobs) protocol to send files and
directories over the internet.

It is also useful as a standalone tool for quick copy jobs.

Iroh will take care of hole punching and NAT traversal whenever possible,
and fall back to a relay if hole punching does not succeed.

Iroh-blobs will take care of [blake3](https://crates.io/crates/blake3) verified
streaming, including resuming interrupted downloads.

Sendme works with 256 bit node ids and is, therefore, location transparent. A ticket
will remain valid if the IP address changes. Connections are encrypted using
TLS.






# WebRTC over Iroh

Sistema di comunicazione peer-to-peer che usa **Iroh** per attraversare NAT e stabilire connessioni WebRTC dirette per streaming audio/video, trasferimento file e messaggi.

## 🎯 Caratteristiche

- **NAT Traversal**: Usa Iroh e magicsocket per attraversare firewall e NAT
- **Ticket System**: Connessione semplice tramite ticket codificati
- **Audio/Video Streaming**: Supporto RTP per media in tempo reale
- **File Transfer**: Trasferimento dati binari tramite data channel
- **Messaggi**: Chat testuale in tempo reale
- **Bidirectional**: Supporto per flussi bidirezionali

## 🏗️ Architettura

```
┌─────────┐                   ┌─────────┐
│ Sender  │                   │Receiver │
│         │                   │         │
│  Iroh   │◄──── SDP/ICE ────►│  Iroh   │
│Endpoint │    (Signaling)    │Endpoint │
└────┬────┘                   └────┬────┘
     │                             │
     │      ┌──────────────┐       │
     └─────►│   WebRTC     │◄──────┘
            │  Connection  │
            │              │
            │ ┌──────────┐ │
            │ │Audio/RTP │ │
            │ ├──────────┤ │
            │ │Video/RTP │ │
            │ ├──────────┤ │
            │ │ Files DC │ │
            │ ├──────────┤ │
            │ │  Msg DC  │ │
            │ └──────────┘ │
            └──────────────┘
```

## 🚀 Utilizzo

### 1. Modalità Send (Host)

Avvia una sessione e genera un ticket:

```bash
# Base (solo file e messaggi)
cargo run -- send

# Con audio e video
cargo run -- send --audio --video

# Con file sharing
cargo run -- send --file --share /path/to/file.mp4

# Custom relay
cargo run -- send --relay https://relay.example.com
```

Output:
```
🚀 Starting sender session...
📋 Your ticket:
MZXW6YTBOI2DKNZTGAZDCNRSHA4DK




























# Installation

```
cargo install sendme
```

# Usage

## Send side

```
sendme send <file or directory>
```

This will create a temporary [iroh](https://crates.io/crates/iroh) node that
serves the content in the given file or directory. It will output a ticket that
can be used to get the data.

The provider will run until it is terminated using `Control-C`. On termination, it
will delete the temporary directory.

This currently will create a temporary directory in the current directory. In
the future this won't be needed anymore.

### Receive side

```
sendme receive <ticket>
```

This will download the data and create a file or directory named like the source
in the **current directory**.

It will create a temporary directory in the current directory, download the data
(single file or directory), and only then move these files to the target
directory.

On completion, it will delete the temp directory.

All temp directories start with `.sendme-`.
