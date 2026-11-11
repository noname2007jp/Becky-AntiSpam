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
    bool trusted_return_path = false;
    bool trusted_authentication_results = false;
};

struct BrandRule {
    std::vector<std::string> aliases;
    std::vector<std::string> allowed_domains;
};

struct Settings {
    int spam_threshold = 60;
    int review_threshold = 30;
    bool enable_authentication_rules = true;
    bool enable_url_rules = true;
    bool enable_bayes_comparison = false;
    bool enable_symbol_comparison = false;
    std::vector<BrandRule> brand_rules;
};

struct Finding {
    std::string rule;
    int score = 0;
    std::string reason;
};

enum class Verdict { Ham, Review, Spam };

struct SymbolScoreComparison {
    int score = 0;
    Verdict verdict = Verdict::Ham;
    int authentication_score = 0;
    int header_score = 0;
    int brand_score = 0;
    int content_score = 0;
    int url_score = 0;
    int bayes_score = 0;
    std::size_t symbol_count = 0;
};

struct BayesDiagnostics {
    std::size_t total_tokens = 0;
    std::size_t known_tokens = 0;
    std::size_t unknown_tokens = 0;
    std::size_t spam_evidence_tokens = 0;
    std::size_t ham_evidence_tokens = 0;
    double log_odds = 0.0;
};

struct BayesComparison {
    double presence_probability = 0.0;
    double bernoulli_probability = 0.0;
    double presence_log_odds = 0.0;
    double bernoulli_log_odds = 0.0;
    double correlation_adjusted_probability = 0.0;
    double correlation_adjusted_log_odds = 0.0;
    double correlation_adjustment_scale = 0.0;
    std::size_t correlation_adjusted_features = 0;
    std::size_t vocabulary_features = 0;
};

struct Result {
    Verdict verdict = Verdict::Ham;
    int score = 0;
    double bayes_probability = 0.0;
    BayesDiagnostics bayes_diagnostics;
    BayesComparison bayes_comparison;
    SymbolScoreComparison symbol_comparison;
    // Privacy-safe diagnostics: booleans/counts only; never retain matched text or domains.
    std::size_t brand_rules_checked = 0;
    bool brand_rule_matched = false;
    bool brand_subject_match = false;
    bool brand_display_match = false;
    bool brand_from_domain_present = false;
    bool brand_from_allowed = false;
    std::size_t brand_url_hosts_checked = 0;
    bool brand_url_domain_mismatch = false;
    std::vector<Finding> findings;
};

class BayesianModel {
public:
    explicit BayesianModel(std::size_t max_vocabulary = 50000);
    void train(const std::string& text, bool spam);
    double spam_probability(const std::string& text, BayesDiagnostics* diagnostics = nullptr) const;
    // Offline comparison only; does not change the active classification result.
    BayesComparison compare_probabilities(const std::string& text) const;
    std::size_t spam_samples() const noexcept { return spam_samples_; }
    std::size_t ham_samples() const noexcept { return ham_samples_; }
    std::size_t vocabulary_size() const noexcept { return words_.size(); }
    std::size_t max_vocabulary() const noexcept { return max_vocabulary_; }
    struct TokenCount { std::string token; std::size_t spam_docs = 0; std::size_t ham_docs = 0; };
    void restore(std::size_t spam_samples, std::size_t ham_samples,
                 const std::vector<TokenCount>& token_counts);
    // Removes low-frequency terms until the requested vocabulary limit is met.
    std::size_t compact(std::size_t max_words, std::size_t min_total_frequency = 1);
    // Applies proportional decay to all learned document counts (0 < factor < 1).
    void decay(double factor);

private:
    struct Counts { std::size_t spam = 0; std::size_t ham = 0; };
    std::unordered_map<std::string, Counts> words_;
    std::size_t spam_samples_ = 0;
    std::size_t ham_samples_ = 0;
    std::size_t max_vocabulary_ = 50000;
};

class Filter {
public:
    explicit Filter(Settings settings = {});
    Result classify(const Message& message, const BayesianModel* model = nullptr) const;

private:
    Settings settings_;
};

std::string classifier_text(const Message& message);
std::vector<std::string> tokenize(const std::string& text);

} // namespace beckyas
