#pragma once

#include "antispam.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace beckyas {

struct HeaderField {
    std::string name;
    std::string value;
};

struct AttachmentInfo {
    std::string filename;
    std::string content_type;
    std::string disposition;
};

struct ParseLimits {
    std::size_t max_message_bytes = 5 * 1024 * 1024;
    std::size_t max_header_bytes = 256 * 1024;
    std::size_t max_header_fields = 200;
    std::size_t max_mime_parts = 100;
    std::size_t max_mime_depth = 8;
    std::size_t max_decoded_text_bytes = 2 * 1024 * 1024;
};

struct ParsedMail {
    Message message;
    std::vector<HeaderField> headers;
    std::vector<AttachmentInfo> attachments;
    std::size_t source_bytes = 0;
    std::size_t mime_parts = 0;
    bool body_truncated = false;
    std::vector<std::string> warnings;
};

class MessageParser {
public:
    explicit MessageParser(ParseLimits limits = {});
    bool parse(const std::string& raw_message, ParsedMail& output,
               std::string* error = nullptr) const;

private:
    ParseLimits limits_;
};

} // namespace beckyas
