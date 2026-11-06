#pragma once

#include <string>
#include <vector>

namespace beckyas {

// Common interface so an optional MeCab adapter can be added without changing
// the Bayesian engine or SQLite storage layer.
class Tokenizer {
public:
    virtual ~Tokenizer() = default;
    virtual std::vector<std::string> split(const std::string& utf8_text) const = 0;
};

// Dependency-free UTF-8 tokenizer. Japanese runs are represented by overlapping
// bigrams; ASCII words and katakana runs are retained as whole tokens.
class SimpleJapaneseTokenizer final : public Tokenizer {
public:
    std::vector<std::string> split(const std::string& utf8_text) const override;
};

std::vector<std::string> tokenize(const std::string& utf8_text);

} // namespace beckyas
