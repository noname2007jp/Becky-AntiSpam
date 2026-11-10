#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "ai_protocol.hpp"

#include <cstdint>
#include <cstdio>
#include <vector>

namespace {

bool read_exact(HANDLE pipe, void* buffer, DWORD bytes) {
    auto* out = static_cast<unsigned char*>(buffer);
    DWORD done = 0;
    while (done < bytes) {
        DWORD received = 0;
        if (!ReadFile(pipe, out + done, bytes - done, &received, nullptr) || received == 0)
            return false;
        done += received;
    }
    return true;
}

bool write_exact(HANDLE pipe, const void* buffer, DWORD bytes) {
    const auto* input = static_cast<const unsigned char*>(buffer);
    DWORD done = 0;
    while (done < bytes) {
        DWORD sent = 0;
        if (!WriteFile(pipe, input + done, bytes - done, &sent, nullptr) || sent == 0)
            return false;
        done += sent;
    }
    return true;
}

bool send_response(HANDLE pipe, beckyas::ai::Status status) {
    const beckyas::ai::ResponseHeader response{
        beckyas::ai::kProtocolMagic,
        beckyas::ai::kProtocolVersion,
        static_cast<std::uint16_t>(status),
        0
    };
    return write_exact(pipe, &response, sizeof(response));
}

bool handle_client(HANDLE pipe) {
    using namespace beckyas::ai;
    RequestHeader request{};
    if (!read_exact(pipe, &request, sizeof(request))) return false;

    if (request.magic != kProtocolMagic ||
        request.version != kProtocolVersion ||
        request.payload_bytes > kMaxFrameBytes) {
        send_response(pipe, Status::InvalidRequest);
        return false;
    }

    std::vector<unsigned char> payload(request.payload_bytes);
    if (!payload.empty() &&
        !read_exact(pipe, payload.data(), static_cast<DWORD>(payload.size()))) return false;

    switch (static_cast<Command>(request.command)) {
    case Command::Ping:
        return send_response(pipe, request.payload_bytes == 0
            ? Status::Ok : Status::InvalidRequest);
    case Command::Classify: {
        if (payload.size() < sizeof(ClassifyPayloadHeader)) {
            return send_response(pipe, Status::InvalidRequest);
        }
        ClassifyPayloadHeader lengths{};
        std::memcpy(&lengths, payload.data(), sizeof(lengths));
        const std::uint64_t expected = sizeof(lengths) +
            static_cast<std::uint64_t>(lengths.subject_bytes) + lengths.body_bytes;
        if (expected != payload.size()) return send_response(pipe, Status::InvalidRequest);

        // Inference is deliberately disabled until a validated fine-tuned ONNX
        // model and its matching Japanese tokenizer are packaged with the worker.
        return send_response(pipe, Status::ModelNotReady);
    }
    case Command::Shutdown:
        return send_response(pipe, Status::Ok);
    default:
        return send_response(pipe, Status::InvalidRequest);
    }
}

} // namespace

int wmain() {
    using namespace beckyas::ai;
    for (;;) {
        HANDLE pipe = CreateNamedPipeW(
            kDefaultPipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, 64 * 1024, 64 * 1024, 1000, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) return 2;

        const BOOL connected = ConnectNamedPipe(pipe, nullptr)
            ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (connected) {
            handle_client(pipe);
            FlushFileBuffers(pipe);
            DisconnectNamedPipe(pipe);
        }
        CloseHandle(pipe);
    }
}
