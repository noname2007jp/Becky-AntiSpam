#include "tokenizer.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <unordered_set>

namespace beckyas {
namespace {

struct Rune {
    std::uint32_t value = 0;
    std::size_t begin = 0;
    std::size_t end = 0;
};

bool decode_one(const std::string& s, std::size_t& pos, Rune& out) {
    if (pos >= s.size()) return false;
    const auto start = pos;
    const auto c = static_cast<unsigned char>(s[pos++]);
    std::uint32_t cp = 0;
    unsigned int extra = 0;
    if (c < 0x80) cp = c;
    else if ((c & 0xe0) == 0xc0) { cp = c & 0x1f; extra = 1; }
    else if ((c & 0xf0) == 0xe0) { cp = c & 0x0f; extra = 2; }
    else if ((c & 0xf8) == 0xf0) { cp = c & 0x07; extra = 3; }
    else return false;
    if (pos + extra > s.size()) return false;
    for (unsigned int i = 0; i < extra; ++i) {
        const auto next = static_cast<unsigned char>(s[pos++]);
        if ((next & 0xc0) != 0x80) return false;
        cp = (cp << 6) | (next & 0x3f);
    }
    // Reject overlong encodings, surrogate values and out-of-range code points.
    if ((extra == 1 && cp < 0x80) || (extra == 2 && cp < 0x800) ||
        (extra == 3 && cp < 0x10000) || cp > 0x10ffff ||
        (cp >= 0xd800 && cp <= 0xdfff)) return false;
    out = {cp, start, pos};
    return true;
}

bool is_hiragana(std::uint32_t c) { return c >= 0x3040 && c <= 0x309f; }
bool is_katakana(std::uint32_t c) {
    return (c >= 0x30a0 && c <= 0x30ff) || (c >= 0x31f0 && c <= 0x31ff) ||
           (c >= 0xff66 && c <= 0xff9d);
}
bool is_kanji(std::uint32_t c) {
    return (c >= 0x3400 && c <= 0x4dbf) || (c >= 0x4e00 && c <= 0x9fff) ||
           (c >= 0xf900 && c <= 0xfaff) || (c >= 0x20000 && c <= 0x2fa1f);
}
bool is_japanese(std::uint32_t c) { return is_hiragana(c) || is_katakana(c) || is_kanji(c); }
bool is_ascii_word(std::uint32_t c) {
    return c < 0x80 && std::isalnum(static_cast<unsigned char>(c)) != 0;
}
std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}
} // namespace

std::vector<std::string> SimpleJapaneseTokenizer::split(const std::string& text) const {
    std::vector<Rune> runes;
    runes.reserve(text.size());
    for (std::size_t pos = 0; pos < text.size();) {
        Rune rune;
        const auto before = pos;
        if (!decode_one(text, pos, rune)) {
            // Skip malformed bytes safely; never merge them into adjacent tokens.
            pos = before + 1;
            continue;
        }
        runes.push_back(rune);
    }

    std::vector<std::string> result;
    std::unordered_set<std::string> seen;
    const auto add = [&result, &seen](std::string token) {
        if (token.empty()) return;
        token = lower_ascii(std::move(token));
        if (seen.insert(token).second) result.push_back(std::move(token));
    };

    for (std::size_t i = 0; i < runes.size();) {
        const auto cp = runes[i].value;
        if (is_ascii_word(cp)) {
            const auto first = i;
            bool has_alpha = false;
            while (i < runes.size() && is_ascii_word(runes[i].value)) {
                const auto c = runes[i].value;
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) has_alpha = true;
                ++i;
            }
            // Pure numeric identifiers are high-cardinality noise.
            if (has_alpha && i - first <= 40)
                add(text.substr(runes[first].begin, runes[i - 1].end - runes[first].begin));
            continue;
        }
        if (is_japanese(cp)) {
            const auto first = i;
            while (i < runes.size() && is_japanese(runes[i].value)) ++i;
            const auto count = i - first;
            // Retain katakana compounds as whole-word features, even inside
            // mixed kanji/kana phrases (e.g. "無料キャンペーン").
            for (std::size_t j = first; j < i;) {
                if (!is_katakana(runes[j].value)) { ++j; continue; }
                const auto kata_begin = j;
                while (j < i && is_katakana(runes[j].value)) ++j;
                if (j - kata_begin >= 2 && j - kata_begin <= 16)
                    add(text.substr(runes[kata_begin].begin,
                                    runes[j - 1].end - runes[kata_begin].begin));
            }
            // Overlapping character bigrams work across kanji/kana boundaries.
            for (std::size_t j = first; j + 1 < i; ++j) {
                if (runes[j + 1].end - runes[j].begin <= 16)
                    add(text.substr(runes[j].begin, runes[j + 1].end - runes[j].begin));
            }
            if (count == 1 && is_kanji(runes[first].value))
                add(text.substr(runes[first].begin, runes[first].end - runes[first].begin));
            continue;
        }
        ++i;
    }
    return result;
}

std::vector<std::string> tokenize(const std::string& text) {
    static const SimpleJapaneseTokenizer tokenizer;
    return tokenizer.split(text);
}

} // namespace beckyas
