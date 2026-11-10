# Local AI Worker Architecture

## Goal

Keep the Becky! plugin as a Win32 DLL and run Japanese BERT inference in a separate x64 process. The first implementation stage establishes the local IPC contract only; it does not classify messages yet.

## Process boundary

- Becky! plugin: Win32/x86.
- AI worker: Windows x64 console process.
- Transport: local Windows named pipe, `\\.\pipe\BeckyAntiSpamAI-v1`.
- Remote pipe clients are rejected with `PIPE_REJECT_REMOTE_CLIENTS`.
- The pipe uses the current user's default Windows security descriptor.
- No HTTP listener, cloud API, or outbound mail-content transfer.

## Wire format

All structures are packed and use little-endian Windows integer representation.

Request header:
- magic: 32-bit protocol marker
- version: 16-bit protocol version
- command: 16-bit command
- payload_bytes: 32-bit payload length (maximum 2 MiB)

Response header:
- magic, version, status, payload_bytes

Commands:
- Ping: empty payload; worker returns OK.
- Classify: payload starts with two 32-bit lengths, followed by UTF-8 subject bytes and UTF-8 body bytes. The complete raw RFC822 message, sender address, and transport headers are not part of this protocol.
- Shutdown: reserved for controlled worker shutdown.

Statuses:
- OK
- MODEL_NOT_READY
- INVALID_REQUEST
- INTERNAL_ERROR

## Current implementation status

The x64 worker validates framing and payload lengths. Ping is available. Classify currently returns MODEL_NOT_READY intentionally. It must not return a guessed Ham/Spam verdict.

## Next stages

1. Add a Win32 named-pipe client with strict connection and inference timeouts.
2. Add worker lifecycle management (start once, reuse while Becky! is running, graceful shutdown).
3. Integrate ONNX Runtime and a fine-tuned Japanese BERT classifier.
4. Add the matching MeCab/UniDic tokenizer and verify its redistribution/licensing requirements.
5. Add deterministic test fixtures and benchmark memory/latency on Core i5-1235U / 8 GB RAM.
6. Connect only Review verdicts initially. On worker failure, retain the existing Review verdict and continue mail processing.
