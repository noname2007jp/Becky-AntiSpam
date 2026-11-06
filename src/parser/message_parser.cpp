#include "message_parser.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>
#include <utility>

namespace beckyas {
namespace {

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}
std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}
bool starts_with_ci(const std::string& value, const char* prefix) {
    const auto n = std::char_traits<char>::length(prefix);
    return value.size() >= n && lower_ascii(value.substr(0, n)) == lower_ascii(prefix);
}
std::string decode_base64(std::string_view input) {
    static constexpr signed char table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    std::string out;
    unsigned int buffer = 0;
    int bits = 0;
    for (unsigned char c : input) {
        if (c == '=' || c == ' ' || c == '\r' || c == '\n' || c == '\t') continue;
        const int v = table[c];
        if (v < 0) continue;
        buffer = (buffer << 6) | static_cast<unsigned int>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buffer >> bits) & 0xff));
        }
    }
    return out;
}
int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
std::string decode_q(std::string_view input) {
    std::string out;
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '_') out.push_back(' ');
        else if (input[i] == '=' && i + 2 < input.size()) {
            const int hi = hex_value(input[i + 1]), lo = hex_value(input[i + 2]);
            if (hi >= 0 && lo >= 0) { out.push_back(static_cast<char>((hi << 4) | lo)); i += 2; }
            else out.push_back(input[i]);
        } else out.push_back(input[i]);
    }
    return out;
}
std::string decode_words(const std::string& input) {
    std::string out;
    std::size_t pos = 0;
    while (pos < input.size()) {
        const auto begin = input.find("=?", pos);
        if (begin == std::string::npos) { out.append(input.substr(pos)); break; }
        out.append(input.substr(pos, begin - pos));
        const auto q1 = input.find('?', begin + 2);
        const auto q2 = q1 == std::string::npos ? q1 : input.find('?', q1 + 1);
        const auto end = q2 == std::string::npos ? q2 : input.find("?=", q2 + 1);
        if (q1 == std::string::npos || q2 == std::string::npos || end == std::string::npos) {
            out.append(input.substr(begin)); break;
        }
        const auto encoding = lower_ascii(input.substr(q1 + 1, q2 - q1 - 1));
        const auto payload = std::string_view(input).substr(q2 + 1, end - q2 - 1);
        if (encoding == "b") out += decode_base64(payload);
        else if (encoding == "q") out += decode_q(payload);
        else out.append(input.substr(begin, end + 2 - begin));
        pos = end + 2;
        // RFC 2047 adjacent encoded-words are separated by ignorable linear whitespace.
        if (pos < input.size() && (input[pos] == ' ' || input[pos] == '\t')) {
            auto next = pos;
            while (next < input.size() && (input[next] == ' ' || input[next] == '\t')) ++next;
            if (input.compare(next, 2, "=?") == 0) pos = next;
        }
    }
    return out;
}
std::string param(const std::string& value, const std::string& key) {
    const auto lower = lower_ascii(value);
    const auto needle = lower_ascii(key) + "=";
    auto pos = lower.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    if (pos < value.size() && value[pos] == '"') {
        const auto end = value.find('"', pos + 1);
        return end == std::string::npos ? value.substr(pos + 1) : value.substr(pos + 1, end - pos - 1);
    }
    auto end = value.find(';', pos);
    return trim(value.substr(pos, end == std::string::npos ? end : end - pos));
}
std::string decode_qp(std::string_view in) {
    std::string out;
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '=' && i + 1 < in.size() && (in[i + 1] == '\r' || in[i + 1] == '\n')) {
            ++i;
            if (i < in.size() && in[i] == '\r' && i + 1 < in.size() && in[i + 1] == '\n') ++i;
        } else if (in[i] == '=' && i + 2 < in.size()) {
            const int hi = hex_value(in[i + 1]), lo = hex_value(in[i + 2]);
            if (hi >= 0 && lo >= 0) { out.push_back(static_cast<char>((hi << 4) | lo)); i += 2; }
            else out.push_back(in[i]);
        } else out.push_back(in[i]);
    }
    return out;
}
std::string decode_transfer(const std::string& body, const std::string& encoding) {
    const auto e = lower_ascii(trim(encoding));
    if (e == "base64") return decode_base64(body);
    if (e == "quoted-printable") return decode_qp(body);
    return body;
}
std::string strip_html(const std::string& html) {
    std::string out;
    bool in_tag = false;
    for (char c : html) {
        if (c == '<') in_tag = true;
        else if (c == '>') { in_tag = false; out.push_back(' '); }
        else if (!in_tag) out.push_back(c);
    }
    return out;
}
bool parse_headers(const std::string& block, std::vector<HeaderField>& fields,
                   std::size_t max_fields, std::vector<std::string>& warnings) {
    std::size_t pos = 0;
    while (pos <= block.size()) {
        const auto end = block.find('\n', pos);
        auto line = block.substr(pos, end == std::string::npos ? end : end - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) {
            if (fields.empty()) warnings.push_back("先頭の継続ヘッダー行を無視しました");
            else fields.back().value += " " + trim(line);
        } else if (!line.empty()) {
            const auto colon = line.find(':');
            if (colon == std::string::npos || colon == 0) warnings.push_back("形式不正なヘッダー行を無視しました");
            else if (fields.size() >= max_fields) { warnings.push_back("ヘッダー数上限に達しました"); return false; }
            else {
                auto name = trim(line.substr(0, colon));
                if (std::any_of(name.begin(), name.end(), [](unsigned char c) {
                    return !(std::isalnum(c) || c == '-');
                })) warnings.push_back("不正なヘッダー名を無視しました");
                else fields.push_back({lower_ascii(name), trim(line.substr(colon + 1))});
            }
        }
        if (end == std::string::npos) break;
        pos = end + 1;
    }
    return true;
}
std::string header_value(const std::vector<HeaderField>& fields, const char* name) {
    for (const auto& f : fields) if (f.name == name) return f.value;
    return {};
}
void append_bounded(std::string& out, const std::string& value, std::size_t limit, bool& truncated) {
    if (out.size() >= limit) { truncated = true; return; }
    const auto n = std::min(limit - out.size(), value.size());
    out.append(value.data(), n);
    if (n < value.size()) truncated = true;
}
struct MimeContext {
    const ParseLimits& limits;
    ParsedMail& output;
    std::string plain;
    std::string html;
};
void parse_entity(const std::string& entity, std::size_t depth, MimeContext& ctx) {
    if (depth > ctx.limits.max_mime_depth || ctx.output.mime_parts >= ctx.limits.max_mime_parts) {
        ctx.output.warnings.push_back("MIMEの深さまたはパート数上限に達しました");
        return;
    }
    ++ctx.output.mime_parts;
    const auto split = entity.find("\r\n\r\n") != std::string::npos
        ? entity.find("\r\n\r\n") : entity.find("\n\n");
    if (split != std::string::npos && split > ctx.limits.max_header_bytes) {
        ctx.output.warnings.push_back("MIMEパートのヘッダーサイズ上限に達しました");
        return;
    }
    std::string header_block, body;
    if (split == std::string::npos) body = entity;
    else {
        header_block = entity.substr(0, split);
        const auto separator = entity.compare(split, 4, "\r\n\r\n") == 0 ? 4u : 2u;
        body = entity.substr(split + separator);
    }
    std::vector<HeaderField> headers;
    parse_headers(header_block, headers, 100, ctx.output.warnings);
    std::string content_type = "text/plain";
    std::string disposition, transfer;
    for (const auto& f : headers) {
        if (f.name == "content-type") content_type = f.value;
        else if (f.name == "content-disposition") disposition = f.value;
        else if (f.name == "content-transfer-encoding") transfer = f.value;
    }
    const auto media_type = lower_ascii(trim(content_type.substr(0, content_type.find(';'))));
    const auto boundary = param(content_type, "boundary");
    if (media_type.rfind("multipart/", 0) == 0 && !boundary.empty()) {
        const std::string marker = "--" + boundary;
        std::size_t pos = 0;
        while ((pos = body.find(marker, pos)) != std::string::npos) {
            pos += marker.size();
            if (body.compare(pos, 2, "--") == 0) break;
            if (body.compare(pos, 2, "\r\n") == 0) pos += 2;
            else if (pos < body.size() && body[pos] == '\n') ++pos;
            const auto next = body.find(marker, pos);
            if (next == std::string::npos) break;
            auto part = body.substr(pos, next - pos);
            while (!part.empty() && (part.back() == '\r' || part.back() == '\n')) part.pop_back();
            parse_entity(part, depth + 1, ctx);
            if (ctx.output.mime_parts >= ctx.limits.max_mime_parts) {
                ctx.output.warnings.push_back("MIMEパート数上限に達したため残りを省略しました");
                break;
            }
            pos = next;
        }
        return;
    }
    const auto filename = param(disposition, "filename").empty()
        ? param(content_type, "name") : param(disposition, "filename");
    if (media_type.rfind("text/", 0) != 0 || lower_ascii(disposition).find("attachment") != std::string::npos ||
        !filename.empty()) {
        ctx.output.attachments.push_back({decode_words(filename), media_type, disposition});
        return;
    }
    auto decoded = decode_transfer(body, transfer);
    if (media_type == "text/html") append_bounded(ctx.html, strip_html(decoded), ctx.limits.max_decoded_text_bytes, ctx.output.body_truncated);
    else if (media_type == "text/plain" || media_type.empty()) append_bounded(ctx.plain, decoded, ctx.limits.max_decoded_text_bytes, ctx.output.body_truncated);
}
} // namespace

MessageParser::MessageParser(ParseLimits limits) : limits_(limits) {}

bool MessageParser::parse(const std::string& raw_message, ParsedMail& output, std::string* error) const {
    output = {};
    output.source_bytes = raw_message.size();
    if (raw_message.size() > limits_.max_message_bytes) {
        if (error) *error = "メールサイズが上限を超えています";
        return false;
    }
    auto split = raw_message.find("\r\n\r\n");
    std::size_t separator = 4;
    if (split == std::string::npos) { split = raw_message.find("\n\n"); separator = 2; }
    if (split == std::string::npos) {
        if (error) *error = "ヘッダーと本文の区切りがありません";
        return false;
    }
    if (split > limits_.max_header_bytes) {
        if (error) *error = "ヘッダーサイズが上限を超えています";
        return false;
    }
    const auto header_block = raw_message.substr(0, split);
    if (!parse_headers(header_block, output.headers, limits_.max_header_fields, output.warnings)) {
        if (error) *error = "ヘッダー数が上限を超えています";
        return false;
    }
    output.message.from = decode_words(header_value(output.headers, "from"));
    output.message.return_path = decode_words(header_value(output.headers, "return-path"));
    output.message.subject = decode_words(header_value(output.headers, "subject"));
    for (const auto& f : output.headers) {
        if (f.name == "authentication-results") {
            output.authentication_results.push_back(f.value);
        }
    }
    // Authentication-Results is attacker-spoofable unless its authserv-id is
    // explicitly trusted by the receiving environment. Do not feed it to rules yet.


    MimeContext ctx{limits_, output};
    // Parse the complete entity so the root Content-Type and transfer-encoding apply.
    parse_entity(raw_message, 0, ctx);
    output.message.body = ctx.plain.empty() ? ctx.html : ctx.plain;
    if (output.body_truncated) output.warnings.push_back("本文テキストを上限で切り詰めました");
    return true;
}

} // namespace beckyas
