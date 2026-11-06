#pragma once

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

namespace beckyas {

struct Message {
    std::string from;
    std::string return_path;
    std::string subject;
    std::string headers;
    std::string body;
    std::string spf_result;
    std::string dkim_result;
    std::string dmarc_result;
};

struct Settings {
    int spam_threshold = 60;
    int review_threshold = 30;
    bool enable_authentication_rules = true;
    bool enable_url_rules = true;
};

struct Finding {
    std::string rule;
    int score = 0;
    std::string reason;
};

enum class Verdict { Ham, Review, Spam };

struct Result {
    Verdict verdict = Verdict::Ham;
    int score = 0;
    double bayes_probability = 0.0;
    std::vector<Finding> findings;
};

class BayesianModel {
public:
    void train(const std::string& text, bool spam);
    double spam_probability(const std::string& text) const;
    std::size_t spam_samples() const noexcept { return spam_samples_; }
    std::size_t ham_samples() const noexcept { return ham_samples_; }

private:
    struct Counts { std::size_t spam = 0; std::size_t ham = 0; };
    std::unordered_map<std::string, Counts> words_;
    std::size_t spam_samples_ = 0;
    std::size_t ham_samples_ = 0;
};

class Filter {
public:
    explicit Filter(Settings settings = {});
    Result classify(const Message& message, const BayesianModel* model = nullptr) const;

private:
    Settings settings_;
};

std::vector<std::string> tokenize(const std::string& text);

} // namespace beckyas
