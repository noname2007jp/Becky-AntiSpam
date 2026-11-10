#pragma once

#include <cstdint>

namespace beckyas::ai {

// Local named-pipe protocol shared by the 32-bit Becky! DLL and 64-bit AI worker.
// All integer fields are little-endian (Windows native byte order).
constexpr wchar_t kDefaultPipeName[] = L"\\\\.\\pipe\\BeckyAntiSpamAI-v1";
constexpr std::uint32_t kProtocolMagic = 0x42415341; // "ASAB" on little-endian
constexpr std::uint16_t kProtocolVersion = 1;
constexpr std::uint32_t kMaxFrameBytes = 2u * 1024u * 1024u;

enum class Command : std::uint16_t {
    Ping = 1,
    Classify = 2,
    Shutdown = 3
};

enum class Status : std::uint16_t {
    Ok = 0,
    ModelNotReady = 1,
    InvalidRequest = 2,
    InternalError = 3
};

#pragma pack(push, 1)
struct RequestHeader {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t command;
    std::uint32_t payload_bytes;
};

struct ResponseHeader {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t status;
    std::uint32_t payload_bytes;
};

// Classify payload: two UTF-8 byte strings concatenated in this order:
// subject, body. Their lengths are carried here. No raw RFC822 message,
// sender address, or transport headers are sent to the worker.
struct ClassifyPayloadHeader {
    std::uint32_t subject_bytes;
    std::uint32_t body_bytes;
};
#pragma pack(pop)

} // namespace beckyas::ai
