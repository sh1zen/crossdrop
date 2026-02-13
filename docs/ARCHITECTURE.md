# Crossdrop Architecture Infographics

This document provides visual representations of the message handling, file transfer pipelines, and remote file request systems in Crossdrop.

---

## Table of Contents

1. [Message Pipeline](#1-message-pipeline)
2. [File Transfer Pipeline](#2-file-transfer-pipeline)
3. [Remote File Request System](#3-remote-file-request-system)
4. [Transaction State Machine](#4-transaction-state-machine)
5. [WebRTC Data Flow](#5-webrtc-data-flow)

---

## 1. Message Pipeline

### 1.1 Message Sending Flow

```
                                    MESSAGE SENDING FLOW
                                    ====================

    UI Layer                    Core Layer                    Transport Layer
    ========                    ==========                    ===============

    Chat Panel                  UIExecuter                    WebRTCConnection
        |                           |                              |
        | send_message()            |                              |
        +-------------------------->|                              |
        |                           |                              |
        |                     EngineAction                        |
        |                           |                              |
        |                           +--- send_control() ----------->|
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     |  Derive HMAC    |
        |                           |                     |  (chat_hmac_key)|
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | Create AuthMsg  |
        |                           |                     | (counter + HMAC)|
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     |  JSON Encode    |
        |                           |                     | ControlMessage  |
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | Brotli Compress |
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | AES-256-GCM     |
        |                           |                     | Encrypt         |
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | WebRTC Send     |
        |                           |                     | (DataChannel)   |
        |                           |                     +-----------------+
```

### 1.2 Message Receiving Flow

```
                                    MESSAGE RECEIVING FLOW
                                    ======================

    Transport Layer                    Core Layer                    UI Layer
    ===============                    ==========                    ========

    WebRTCConnection                   TransferEngine               App/Chat Panel
        |                                    |                            |
        | on_message callback                |                            |
        +------------------------------------>|                            |
        |                                    |                            |
        +--------v--------+                  |                            |
        | AES-256-GCM     |                  |                            |
        | Decrypt         |                  |                            |
        +--------+--------+                  |                            |
        |                                    |                            |
        +--------v--------+                  |                            |
        | Brotli Decompress|                 |                            |
        +--------+--------+                  |                            |
        |                                    |                            |
        +--------v--------+                  |                            |
        | Frame Type Check|                  |                            |
        +--------+--------+                  |                            |
        |                                    |                            |
        |    FRAME_CONTROL                   |                            |
        +-----------> ControlMessage         |                            |
        |                                    |                            |
        +--------v--------+                  |                            |
        | Verify HMAC      |                 |                            |
        | Check Counter    |                 |                            |
        | (Replay Protect) |                 |                            |
        +--------+--------+                  |                            |
        |                                    |                            |
        |     ConnectionMessage              |                            |
        |     .TextReceived(data)            |                            |
        +----------------------------------->|                            |
        |                                    |                            |
        |                              AppEvent                           |
        |                              .ChatReceived                   |
        |                                    +--------------------------->|
        |                                    |                            |
        |                                    |                     Update UI
        |                                    |                     (Chat Panel)
```

### 1.3 Message Types

```
                                    CONTROL MESSAGE TYPES
                                    =====================

    ControlMessage Enum
    ===================
    |
    +-- Text(Vec<u8>)                    : Plain chat message (broadcast)
    |
    +-- DirectMessage(Vec<u8>)           : 1-to-1 direct message
    |
    +-- AuthenticatedText(Vec<u8>)       : HMAC + counter protected broadcast
    |
    +-- AuthenticatedDm(Vec<u8>)         : HMAC + counter protected DM
    |
    +-- Typing                           : Ephemeral typing indicator
    |
    +-- DisplayName(String)              : Peer display name announcement
    |
    +-- TransactionRequest {...}         : File/folder transfer request
    |
    +-- TransactionResponse {...}        : Accept/reject transfer
    |
    +-- TransactionComplete {...}       : Transfer completion notice
    |
    +-- TransactionCancel {...}         : Transfer cancellation
    |
    +-- TransactionResumeRequest {...}  : Resume interrupted transfer
    |
    +-- TransactionResumeResponse {...} : Resume acceptance
    |
    +-- Metadata {...}                  : File metadata before chunks
    |
    +-- Hash {...}                      : File integrity hash (SHA3-256 + Merkle)
    |
    +-- HashResult {...}                : Hash verification result
    |
    +-- LsRequest {path}                : Remote directory listing request
    |
    +-- LsResponse {path, entries}      : Remote directory listing response
    |
    +-- FetchRequest {path, is_folder}  : Remote file/folder fetch request
    |
    +-- RemoteAccessDisabled            : Remote access denied notice
    |
    +-- KeyRotation {ephemeral_pub}     : Session key rotation
    |
    +-- ChunkRetransmitRequest {file_id}: Request file retransmission
    |
    +-- TransactionCompleteAck {...}    : Acknowledge transfer completion
    |
    +-- AreYouAwake                     : Liveness probe request
    |
    +-- ImAwake                         : Liveness probe response
```

---

## 2. File Transfer Pipeline

### 2.1 Outbound File Transfer (Sender Side)

```
                                    OUTBOUND FILE TRANSFER
                                    ======================

    UI Layer                    Core Layer                    Transport Layer
    ========                    ==========                    ===============

    Send Panel                  TransferEngine                WebRTCConnection
        |                           |                              |
        | initiate_file_send()      |                              |
        +-------------------------->|                              |
        |                           |                              |
        |                     +-----v-----+                        |
        |                     | Create    |                        |
        |                     | Transaction|                       |
        |                     +-----+-----+                        |
        |                           |                              |
        |                     +-----v-----+                        |
        |                     | Sign      |                        |
        |                     | Manifest  |                        |
        |                     +-----+-----+                        |
        |                           |                              |
        |                     EngineAction                        |
        |                     .SendTransactionRequest              |
        |                           +-----------> ControlMessage  |
        |                           |             .TransactionRequest
        |                           |             --------------->|
        |                           |                              |
        |                           |                     Peer accepts
        |                           |                              |
        |                           |<---- TransactionAccepted ----|
        |                           |                              |
        |                     +-----v-----+                        |
        |                     | Activate  |                        |
        |                     | Transaction|                       |
        |                     +-----+-----+                        |
        |                           |                              |
        |                     EngineAction                        |
        |                     .SendFileData                       |
        |                           |                              |
        |                           +-----------> send_file() ---->|
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | Spawn Disk      |
        |                           |                     | Reader Task     |
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | Send Metadata   |
        |                           |                     | (ControlMessage)|
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |            +-----------------v-----------------+
        |                           |            |         CHUNK LOOP               |
        |                           |            |  +--------------------------+    |
        |                           |            |  | Read chunk from disk     |    |
        |                           |            |  +------------+-------------+    |
        |                           |            |               |                  |
        |                           |            |  +------------v-------------+    |
        |                           |            |  | SHA3-256 hash (per chunk)|    |
        |                           |            |  +------------+-------------+    |
        |                           |            |               |                  |
        |                           |            |  +------------v-------------+    |
        |                           |            |  | Encode chunk frame       |    |
        |                           |            |  | [FRAME_CHUNK|UUID|SEQ|DATA] |
        |                           |            |  +------------+-------------+    |
        |                           |            |               |                  |
        |                           |            |  +------------v-------------+    |
        |                           |            |  | AES-256-GCM encrypt      |    |
        |                           |            |  +------------+-------------+    |
        |                           |            |               |                  |
        |                           |            |  +------------v-------------+    |
        |                           |            |  | WebRTC send (backpressure)|   |
        |                           |            |  +------------+-------------+    |
        |                           |            |               |                  |
        |                           |            |  +------------v-------------+    |
        |                           |            |  | Progress report every    |    |
        |                           |            |  | PIPELINE_SIZE chunks     |    |
        |                           |            |  +--------------------------+    |
        |                           |            +-----------------+----------------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | Send Hash       |
        |                           |                     | (SHA3-256 +     |
        |                           |                     |  Merkle Root)   |
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | Wait HashResult |
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |<---- HashResult {ok: true} ---|
        |                           |                              |
        |                     +-----v-----+                        |
        |                     | Complete  |                        |
        |                     | File      |                        |
        |                     +-----+-----+                        |
        |                           |                              |
        |                     EngineAction                        |
        |                     .SendTransactionComplete            |
        |                           +-----------> ControlMessage  |
        |                           |             .TransactionComplete
        |                           |             --------------->|
        |                           |                              |
        |                           |<---- TransactionCompleteAck -|
        |                           |                              |
        |                     +-----v-----+                        |
        |                     | Archive   |                        |
        |                     | Transaction|                       |
        |                     +-----------+                        |
```

### 2.2 Inbound File Transfer (Receiver Side)

```
                                    INBOUND FILE TRANSFER
                                    =====================

    Transport Layer                    Core Layer                    UI Layer
    ===============                    ==========                    ========

    WebRTCConnection                   TransferEngine               App/Files Panel
        |                                    |                            |
        |<--- TransactionRequest -----------|                            |
        |                                    |                            |
        |     ConnectionMessage              |                            |
        |     .TransactionRequested          |                            |
        +----------------------------------->|                            |
        |                                    |                            |
        |                              +-----v-----+                      |
        |                              | Validate   |                     |
        |                              | Manifest   |                     |
        |                              | Signature  |                     |
        |                              +-----+-----+                      |
        |                                    |                            |
        |                              +-----v-----+                      |
        |                              | Create     |                     |
        |                              | PendingIncoming                    |
        |                              +-----+-----+                      |
        |                                    |                            |
        |                              AppEvent                       |
        |                              .TransactionRequested         |
        |                                    +--------------------------->|
        |                                    |                     Show popup
        |                                    |                     (Accept/Reject)
        |                                    |                            |
        |                                    |<--- User accepts -----------|
        |                                    |                            |
        |                              +-----v-----+                      |
        |                              | Create     |                     |
        |                              | Inbound    |                     |
        |                              | Transaction|                     |
        |                              +-----+-----+                      |
        |                                    |                            |
        |                              EngineAction                      |
        |                              .PrepareReceive                   |
        |                              .SendTransactionResponse          |
        |<-----------------------------------+                            |
        |                                    |                            |
        |     TransactionResponse (accepted)|                            |
        |     ----------------------------->|                            |
        |                                    |                            |
        |     Metadata {file_id, ...}        |                            |
        |<-----------------------------------|                            |
        |                                    |                            |
        +--------v--------+                  |                            |
        | Create           |                  |                            |
        | StreamingFileWriter                 |                            |
        | (sparse temp file)                 |                            |
        +--------+--------+                  |                            |
        |                                    |                            |
        |            +-----------------------v-----------------------+    |
        |            |              CHUNK RECEPTION                 |    |
        |            |  +--------------------------+                |    |
        |            |  | Receive chunk frame      |                |    |
        |            |  +------------+-------------+                |    |
        |            |               |                              |    |
        |            |  +------------v-------------+                |    |
        |            |  | Decrypt (AES-256-GCM)    |                |    |
        |            |  +------------+-------------+                |    |
        |            |               |                              |    |
        |            |  +------------v-------------+                |    |
        |            |  | Parse: [UUID|SEQ|DATA]   |                |    |
        |            |  +------------+-------------+                |    |
        |            |               |                              |    |
        |            |  +------------v-------------+                |    |
        |            |  | Check bitmap (duplicate) |                |    |
        |            |  +------------+-------------+                |    |
        |            |               |                              |    |
        |            |  +------------v-------------+                |    |
        |            |  | SHA3-256 hash (per chunk)|                |    |
        |            |  +------------+-------------+                |    |
        |            |               |                              |    |
        |            |  +------------v-------------+                |    |
        |            |  | Buffer in memory         |                |    |
        |            |  | (BTreeMap<seq, data>)    |                |    |
        |            |  +------------+-------------+                |    |
        |            |               |                              |    |
        |            |  +------------v-------------+                |    |
        |            |  | Flush to disk when       |                |    |
        |            |  | sequential or buffer full|                |    |
        |            |  +------------+-------------+                |    |
        |            |               |                              |    |
        |            |  +------------v-------------+                |    |
        |            |  | Progress report          |                |    |
        |            |  +--------------------------+                |    |
        |            +-----------------------+-----------------------+    |
        |                                    |                            |
        |     Hash {sha3_256, merkle_root}   |                            |
        |<-----------------------------------|                            |
        |                                    |                            |
        +--------v--------+                  |                            |
        | finalize()       |                  |                            |
        | - Flush buffer   |                  |                            |
        | - Read back file |                  |                            |
        | - Compute SHA3   |                  |                            |
        | - Build Merkle   |                  |                            |
        | - Verify match   |                  |                            |
        +--------+--------+                  |                            |
        |                                    |                            |
        |     HashResult {ok: true/false}    |                            |
        |----------------------------------->|                            |
        |                                    |                            |
        |                              +-----v-----+                      |
        |                              | commit()   |                     |
        |                              | atomic rename                    |
        |                              | temp -> final                     |
        |                              +-----+-----+                      |
        |                                    |                            |
        |                              AppEvent                       |
        |                              .FileComplete                  |
        |                                    +--------------------------->|
        |                                    |                     Update UI
```

### 2.3 File Chunk Frame Format

```
                                    CHUNK FRAME FORMAT
                                    ==================

    Wire Format (after encryption envelope):
    ========================================

    +--------+--------+--------+------------------+
    | 1 byte | 16 bytes| 4 bytes|    N bytes       |
    +--------+--------+--------+------------------+
    | Frame  | File   | Chunk  |   Chunk Data     |
    | Type   | UUID   | Seq    |   (up to 48KB)   |
    +--------+--------+--------+------------------+
    | 0x02   | UUID   | BE u32 |   Raw bytes      |
    | (CHUNK)|        |        |                  |
    +--------+--------+--------+------------------+

    Encryption Envelope:
    ====================

    +--------+----------------+------------------+
    | 1 byte |   12 bytes     |   N bytes        |
    +--------+----------------+------------------+
    | Compress| Nonce         |   Ciphertext     |
    | Flag    | (random)      |   (AES-256-GCM)  |
    +--------+----------------+------------------+
    | 0x00 or|                |                  |
    | 0x01   |                |                  |
    +--------+----------------+------------------+

    Compression:
    - 0x00 = No compression (file chunks)
    - 0x01 = Brotli compressed (control messages)
```

### 2.4 Streaming File Writer Memory Model

```
                                    STREAMING FILE WRITER
                                    =====================

    Memory Usage Per File:
    ======================

    +-------------------+-------------------+-------------------+
    | Chunk Hashes      | Chunk Bitmap      | Write Buffer      |
    | O(chunks × 32B)   | O(chunks / 8)     | O(buffer_chunks)  |
    +-------------------+-------------------+-------------------+

    Example: 1GB file (48KB chunks)
    - Total chunks: ~21,845
    - Chunk hashes: 21,845 × 32 = ~684 KB
    - Chunk bitmap: 21,845 / 8 = ~2.7 KB
    - Write buffer: 16 chunks × 48KB = 768 KB
    - Total RAM: ~1.4 MB (vs 1GB in-memory approach)

    Write Buffer Strategy:
    ======================

    +-------------------+
    | BTreeMap<seq, data>|
    +---------+---------+
              |
    +---------v---------+     +-------------------+
    | Flush when:       |---->| Sequential write  |
    | - seq == expected |     | (coalesced I/O)   |
    | - buffer >= limit |     +-------------------+
    +-------------------+

    Disk Layout:
    ============

    +-------------------+
    | Sparse Temp File   |
    | (.crossdrop-tmp)  |
    +---------+---------+
              |
    +---------v---------+     +-------------------+
    | Chunks written    |---->| Finalize:         |
    | at correct offset |     | - Sync to disk    |
    | (seek + write)    |     | - Read back       |
    +-------------------+     | - Compute SHA3    |
                              | - Atomic rename   |
                              +-------------------+
```

---

## 3. Remote File Request System

### 3.1 Remote Directory Listing Flow

```
                                    REMOTE LS FLOW
                                    ==============

    Local Peer                                    Remote Peer
    ==========                                    ===========

    Remote Panel                                  WebRTCConnection
        |                                              |
        | list_remote_directory(peer_id, path)         |
        +--------------------------------------------->|
        |                                              |
        |                                     +--------v--------+
        |                                     | Check           |
        |                                     | remote_access   |
        |                                     +--------+--------+
        |                                              |
        |                              +-------+-------+-------+
        |                              |                       |
        |                     +--------v--------+     +--------v--------+
        |                     | Access Enabled  |     | Access Disabled  |
        |                     +--------+--------+     +--------+--------+
        |                              |                       |
        |                     +--------v--------+     +--------v--------+
        |                     | Read directory  |     | Send            |
        |                     | entries         |     | RemoteAccessDisabled
        |                     +--------+--------+     +--------+--------+
        |                              |                       |
        |                     +--------v--------+             |
        |                     | Send LsResponse |             |
        |                     | {path, entries} |             |
        |                     +--------+--------+             |
        |                                              |
        |<---------------------------------------------|
        |     LsResponse {path, entries}                |
        |                                              |
        +--------v--------+                            |
        | Update UI       |                            |
        | (remote_entries)|                            |
        +-----------------+                            |
```

### 3.2 Remote File Fetch Flow

```
                                    REMOTE FILE FETCH FLOW
                                    ======================

    Local Peer (Receiver)                         Remote Peer (Sender)
    =====================                         ====================

    Remote Panel                                  TransferEngine
        |                                              |
        | User selects file, confirms save path        |
        |                                              |
        +--------v--------+                            |
        | Create          |                            |
        | RemoteFileRequest|                           |
        +--------+--------+                            |
        |                                              |
        | send_control(FetchRequest {path, is_folder}) |
        +--------------------------------------------->|
        |                                              |
        |                                     +--------v--------+
        |                                     | Check           |
        |                                     | remote_access   |
        |                                     +--------+--------+
        |                                              |
        |                                     +--------v--------+
        |                                     | Create          |
        |                                     | Transaction     |
        |                                     | (outbound)      |
        |                                     +--------+--------+
        |                                              |
        |                                     +--------v--------+
        |                                     | Send            |
        |                                     | TransactionRequest
        |                                     +--------+--------+
        |                                              |
        |<---------------------------------------------|
        |     TransactionRequest {manifest, ...}       |
        |                                              |
        +--------v--------+                            |
        | Show popup      |                            |
        | (Accept/Reject) |                            |
        +--------+--------+                            |
        |                                              |
        | User accepts                                 |
        |                                              |
        +--------v--------+                            |
        | Create          |                            |
        | Inbound         |                            |
        | Transaction     |                            |
        +--------+--------+                            |
        |                                              |
        | send_control(TransactionResponse {accepted}) |
        +--------------------------------------------->|
        |                                              |
        |                                     +--------v--------+
        |                                     | Activate        |
        |                                     | Transaction     |
        |                                     +--------+--------+
        |                                              |
        |                                     +--------v--------+
        |                                     | Send file data |
        |                                     | (normal file   |
        |                                     |  transfer flow)|
        |                                     +-----------------+
        |                                              |
        |<---- Metadata, Chunks, Hash -----------------|
        |                                              |
        | (Normal inbound file transfer continues...)  |
```

### 3.3 Remote Folder Fetch Flow

```
                                    REMOTE FOLDER FETCH FLOW
                                    ========================

    Local Peer (Receiver)                         Remote Peer (Sender)
    =====================                         ====================

        |                                              |
        | send_control(FetchRequest {path, is_folder: true})
        +--------------------------------------------->|
        |                                              |
        |                                     +--------v--------+
        |                                     | Scan folder     |
        |                                     | recursively     |
        |                                     +--------+--------+
        |                                              |
        |                                     +--------v--------+
        |                                     | Build manifest  |
        |                                     | (all files with |
        |                                     |  relative paths)|
        |                                     +--------+--------+
        |                                              |
        |                                     +--------v--------+
        |                                     | Create          |
        |                                     | Transaction     |
        |                                     | (folder type)   |
        |                                     +--------+--------+
        |                                              |
        |<---- TransactionRequest {manifest, parent_dir}|
        |                                              |
        | (Same flow as single file, but with          |
        |  multiple files in manifest)                 |
        |                                              |
        |                                     +--------v--------+
        |                                     | Send each file  |
        |                                     | sequentially    |
        |                                     | with relative   |
        |                                     | paths preserved |
        |                                     +-----------------+
```

---

## 4. Transaction State Machine

### 4.1 Transaction States

```
                                    TRANSACTION STATE MACHINE
                                    ========================

                                    +------------+
                                    |   Pending  |
                                    +-----+------+
                                          |
                     +--------------------+--------------------+
                     |                                         |
            +--------v--------+                       +--------v--------+
            | TransactionAccepted                     | TransactionRejected
            | (peer accepted) |                       | (peer declined) |
            +--------+--------+                       +--------+--------+
                     |                                         |
            +--------v--------+                       +--------v--------+
            |     Active      |                       |    Rejected     |
            | (transferring)  |                       |    (terminal)   |
            +--------+--------+                       +-----------------+
                     |
         +-----------+-----------+-----------+
         |           |           |           |
    +----v----+ +----v----+ +----v----+ +----v----+
    | Complete| | Cancel  | | Error   | | Disconnect
    | (all OK)| | (user)  | | (fail)  | | (network)
    +----+----+ +----+----+ +----+----+ +----+----+
         |           |           |           |
         |           |           |    +------v------+
         |           |           |    | Interrupted |
         |           |           |    +------+------+
         |           |           |           |
    +----v----+ +----v----+ +----v----+      |
    |Completed| |Cancelled| | Failed  | +-----v-----+
    |(terminal)| |(terminal)| |(terminal)| | Resumable |
    +---------+ +---------+ +---------+ +-----+-----+
                                              |
                                    +---------v----------+
                                    | Peer Reconnects     |
                                    +---------+----------+
                                              |
                           +------------------+------------------+
                           |                                     |
                    +------v------+                       +------v------+
                    | Resume      |                       | Resume      |
                    | (inbound)   |                       | (outbound)  |
                    +------+------+                       +------+------+
                           |                                     |
                    +------v------+                       +------v------+
                    | Send        |                       | Wait for    |
                    | ResumeRequest|                      | ResumeRequest
                    +------+------+                       +------+------+
                           |                                     |
                    +------v------+                       +------v------+
                    | ResumeAccepted|                     | Process     |
                    +------+------+                       | ResumeRequest
                           |                              +------+------+
                    +------v------+                              |
                    | Reactivate  |                       +------v------+
                    | Transaction |                       | ResendFiles |
                    +-------------+                       +-------------+
```

### 4.2 Transaction Lifecycle Events

```
                                    TRANSACTION LIFECYCLE
                                    =====================

    Outbound Transaction (Sending):
    ===============================

    1. initiate_file_send() / initiate_folder_send()
       -> State: Pending
       -> Action: SendTransactionRequest

    2. TransactionAccepted received
       -> State: Active
       -> Action: SendFileData / SendFolderData

    3. FileProgress events (during transfer)
       -> State: Active (ongoing)
       -> Persist every 20 chunks

    4. SendComplete received (per file)
       -> Mark file complete
       -> If all files done: SendTransactionComplete

    5. TransactionCompleteAcked received
       -> State: Completed
       -> Archive transaction

    -- Error Paths --

    3a. TransactionRejected received
        -> State: Rejected
        -> Archive transaction

    3b. TransactionCancelled received
        -> State: Cancelled
        -> Archive transaction

    3c. PeerDisconnected event
        -> State: Interrupted -> Resumable
        -> Persist for resume

    -- Resume Path --

    4a. PeerReconnected + Resumable transaction
        -> Wait for TransactionResumeRequested

    4b. TransactionResumeRequested received
        -> Validate resume request
        -> Action: AcceptResume + ResendFiles
        -> State: Active

    Inbound Transaction (Receiving):
    ================================

    1. TransactionRequested received
       -> State: Pending (in PendingIncoming)
       -> Show popup to user

    2. User accepts (accept_incoming)
       -> State: Active
       -> Action: PrepareReceive + SendTransactionResponse(accepted)

    3. FileProgress events (during transfer)
       -> State: Active (ongoing)
       -> Persist every 20 chunks

    4. FileComplete received (per file)
       -> Mark file complete
       -> If all files done: State = Completed

    5. TransactionComplete received
       -> Send TransactionCompleteAck
       -> Archive transaction

    -- Resume Path --

    4a. PeerDisconnected event
        -> State: Interrupted -> Resumable
        -> Persist for resume

    4b. PeerReconnected + Resumable inbound
        -> Action: PrepareReceive + SendResumeRequest

    4c. TransactionResumeAccepted received
        -> State: Active
        -> Wait for incoming chunks
```

---

## 5. WebRTC Data Flow

### 5.1 Connection Architecture

```
                                    WEBRTC CONNECTION ARCHITECTURE
                                    ==============================

    +-------------------------------------------------------------------+
    |                         WebRTCConnection                          |
    +-------------------------------------------------------------------+
    |                                                                   |
    |  +---------------------+        +---------------------+           |
    |  |   Control Channel   |        |    Data Channel     |           |
    |  |   (JSON messages)   |        |   (Binary chunks)  |           |
    |  +----------+----------+        +----------+----------+           |
    |             |                              |                       |
    |  +----------v----------+        +----------v----------+           |
    |  | ControlMessage      |        | Chunk Frames        |           |
    |  | - Text/DM           |        | - FRAME_CHUNK       |           |
    |  | - Transaction*      |        | - [UUID|SEQ|DATA]   |           |
    |  | - Metadata          |        +---------------------+           |
    |  | - Hash              |                                          |
    |  | - LsRequest/Response|                                          |
    |  | - FetchRequest      |                                          |
    |  +---------------------+                                          |
    |                                                                   |
    |  +---------------------+        +---------------------+           |
    |  | Shared Key          |        | Key Manager         |           |
    |  | (AES-256-GCM)       |        | (Session Key        |           |
    |  |                     |        |  Rotation)          |           |
    |  +---------------------+        +---------------------+           |
    |                                                                   |
    |  +---------------------+        +---------------------+           |
    |  | Receive State       |        | Accepted            |           |
    |  | HashMap<UUID,       |        | Destinations        |           |
    |  |   ReceiveFileState> |        | HashMap<UUID, Path> |           |
    |  +---------------------+        +---------------------+           |
    |                                                                   |
    |  +---------------------+        +---------------------+           |
    |  | Wire Statistics     |        | Chat Counters       |           |
    |  | (TX/RX bytes)       |        | (send/recv)         |           |
    |  +---------------------+        +---------------------+           |
    +-------------------------------------------------------------------+
                                    |
                                    v
    +-------------------------------------------------------------------+
    |                         RTCPeerConnection                        |
    +-------------------------------------------------------------------+
    |                                                                   |
    |  +---------------------+        +---------------------+           |
    |  | ICE Candidates      |        | SCTP Transport      |           |
    |  | (STUN/TURN)         |        | (Data Channels)    |           |
    |  +---------------------+        +---------------------+           |
    |                                                                   |
    +-------------------------------------------------------------------+
```

### 5.2 Encryption Pipeline

```
                                    ENCRYPTION PIPELINE
                                    ===================

    Outbound (Sending):
    ===================

    +-------------+     +-------------+     +-------------+     +-------------+
    | Plaintext   | --> | Brotli      | --> | AES-256-GCM | --> | WebRTC      |
    | (message/   |     | Compress    |     | Encrypt     |     | Send        |
    |  chunk)     |     | (optional)  |     |             |     |             |
    +-------------+     +-------------+     +-------------+     +-------------+
                            |                    |
                            v                    v
                     +-------------+     +-------------+
                     | 0x01 flag   |     | Nonce (12B) |
                     | if compressed|    | + Ciphertext|
                     +-------------+     +-------------+

    Wire Format:
    ============

    +--------+------------+------------------+
    | 1 byte |  12 bytes  |    N bytes       |
    +--------+------------+------------------+
    | Compress| Nonce      | Encrypted        |
    | Flag    | (random)   | Payload          |
    +--------+------------+------------------+

    Inbound (Receiving):
    ====================

    +-------------+     +-------------+     +-------------+     +-------------+
    | WebRTC      | --> | AES-256-GCM | --> | Brotli      | --> | Plaintext   |
    | Receive     |     | Decrypt     |     | Decompress  |     | (message/   |
    |             |     |             |     | (if flag)   |     |  chunk)     |
    +-------------+     +-------------+     +-------------+     +-------------+
```

### 5.3 Backpressure Handling

```
                                    BACKPRESSURE MECHANISM
                                    ======================

    Sender Side:
    ============

    +-------------------+
    | Check buffered_amount
    +--------+----------+
             |
    +--------v----------+     +-------------------+
    | buffered + next   | --> | Send immediately  |
    | <= HIGH_WATERMARK |     | (no wait)         |
    +--------+----------+     +-------------------+
             |
             | (else)
    +--------v----------+
    | Wait for buffer   |
    | to drain          |
    +--------+----------+
             |
    +--------v----------+
    | Poll every 100ms  |
    | (max 10 seconds)  |
    +--------+----------+
             |
    +--------v----------+     +-------------------+
    | Channel still     | --> | Proceed with send |
    | open?             |     | (timeout)         |
    +--------+----------+     +-------------------+
             |
             | (else)
    +--------v----------+
    | Return error      |
    | (channel closed)  |
    +-------------------+

    Constants:
    ==========

    DC_BUFFERED_AMOUNT_HIGH = 1MB
    - Maximum buffered data before applying backpressure

    DC_SEND_MAX_RETRIES = 3
    - Retries for transient "not open" errors

    DC_REOPEN_TIMEOUT = 5 seconds
    - Time to wait for channel to reopen
```

---

## 6. Data Structures Summary

### 6.1 Key Types

```
                                    KEY DATA STRUCTURES
                                    ===================

    Transaction:
    ============
    +-------------------+-------------------+
    | id: Uuid          | state: TransactionState
    | direction: Direction| peer_id: String   |
    | display_name: Str | parent_dir: Option|
    | total_size: u64   | dest_path: Option |
    | file_order: Vec<Uuid>| files: HashMap<Uuid, TransactionFile>
    | created_at: Instant| resumed_at: Option|
    +-------------------+-------------------+

    TransactionFile:
    ================
    +-------------------+-------------------+
    | file_id: Uuid     | relative_path: Str|
    | filesize: u64     | total_chunks: u32 |
    | transferred_chunks| completed: bool   |
    | verified: Option  | chunk_bitmap: Option
    | merkle_root: Option| retransmit_count |
    +-------------------+-------------------+

    TransactionManifest:
    ====================
    +-------------------+-------------------+
    | files: Vec<ManifestEntry>| parent_dir: Option
    | sender_id: Option | signature: Option |
    | nonce_seed: Option| expiration_time   |
    +-------------------+-------------------+

    ResumeInfo:
    ===========
    +-------------------+-------------------+
    | transaction_id    | completed_files   |
    | partial_offsets   | partial_checksums |
    | chunk_bitmaps     | hmac: Option      |
    | receiver_signature|                   |
    +-------------------+-------------------+

    StreamingFileWriter:
    ====================
    +-------------------+-------------------+
    | file: File        | temp_path: PathBuf|
    | final_path: PathBuf| filesize: u64     |
    | total_chunks: u32 | received_chunks   |
    | chunk_hashes: Vec | bitmap: ChunkBitmap
    | write_buffer: BTreeMap| next_flush_seq |
    +-------------------+-------------------+

    ReceiveFileState:
    =================
    +-------------------+-------------------+
    | writer: StreamingFileWriter| pending_hash: Option
    +-------------------+-------------------+
```

---

## 7. Configuration Constants

```
                                    CONFIGURATION CONSTANTS
                                    =======================

    Transfer Settings:
    ==================
    CHUNK_SIZE = 48KB
    - Size of each file chunk

    MAX_CONCURRENT_TRANSACTIONS = 3
    - Maximum simultaneous transfers

    MAX_FILE_RETRANSMISSIONS = 3
    - Retries before marking file as failed

    MAX_TRANSACTION_RETRIES = 5
    - Resume attempts before giving up

    TRANSACTION_TIMEOUT = 5 minutes
    - Manifest expiration time

    Pipeline Settings:
    ==================
    PIPELINE_SIZE = 8
    - Chunks per progress report batch

    SENDER_READ_AHEAD_CHUNKS = 16
    - Prefetch buffer size for disk reader

    RECEIVER_WRITE_BUFFER_CHUNKS = 16
    - In-memory write buffer capacity

    WebRTC Settings:
    ================
    DC_BUFFERED_AMOUNT_HIGH = 1MB
    - Backpressure threshold

    DC_SEND_MAX_RETRIES = 3
    - Transient error retries

    DC_REOPEN_TIMEOUT = 5 seconds
    - Channel reopen wait time

    AWAKE_CHECK_TIMEOUT = 5 seconds
    - Liveness probe timeout

    Pending Chunk Limits:
    =====================
    MAX_PENDING_FILE_IDS = 10
    - Maximum files with pending chunks

    MAX_PENDING_CHUNKS_PER_FILE = 100
    - Maximum buffered chunks per file
```

---

This document provides a comprehensive visual reference for understanding the Crossdrop architecture. For implementation details, refer to the source code in the respective modules.