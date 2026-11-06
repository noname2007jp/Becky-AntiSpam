#include "antispam.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <regex>
#include <unordered_set>

namespace beckyas {
namespace {
std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}
bool contains(const std::string& haystack, const std::string& needle) {
    return lower(haystack).find(needle) != std::string::npos;
}
std::string combined_text(const Message& m) {
    return m.subject + "\n" + m.headers + "\n" + m.body;
}
void add(Result& r, const char* id, int score, const char* reason) {
    r.score += score;
    r.findings.push_back({id, score, reason});
}
} // namespace

std::vector<std::string> tokenize(const std::string& text) {
    std::vector<std::string> out;
    std::string token;
    for (unsigned char c : lower(text)) {
        if (std::isalnum(c) || c >= 0x80) token.push_back(static_cast<char>(c));
        else if (token.size() >= 2) { out.push_back(token); token.clear(); }
        else token.clear();
    }
    if (token.size() >= 2) out.push_back(token);
    return out;
}

BayesianModel::BayesianModel(std::size_t max_vocabulary)
    : max_vocabulary_(std::max<std::size_t>(1, max_vocabulary)) {}

void BayesianModel::train(const std::string& text, bool spam) {
    if (spam) ++spam_samples_; else ++ham_samples_;
    std::unordered_set<std::string> unique;
    for (const auto& word : tokenize(text)) unique.insert(word);
    for (const auto& word : unique) {
        auto& count = words_[word];
        if (spam) ++count.spam; else ++count.ham;
    }
    if (words_.size() > max_vocabulary_) compact(max_vocabulary_);
}

std::size_t BayesianModel::compact(std::size_t max_words, std::size_t min_total_frequency) {
    std::vector<std::pair<std::string, std::size_t>> ranked;
    ranked.reserve(words_.size());
    for (const auto& entry : words_) {
        const auto total = entry.second.spam + entry.second.ham;
        if (total < min_total_frequency) continue;
        ranked.emplace_back(entry.first, total);
    }
    std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });

    std::unordered_set<std::string> keep;
    const auto keep_count = std::min(max_words, ranked.size());
    keep.reserve(keep_count);
    for (std::size_t i = 0; i < keep_count; ++i) keep.insert(ranked[i].first);

    const auto before = words_.size();
    for (auto it = words_.begin(); it != words_.end();) {
        if (keep.find(it->first) == keep.end()) it = words_.erase(it);
        else ++it;
    }
    max_vocabulary_ = std::max<std::size_t>(1, max_words);
    return before - words_.size();
}

void BayesianModel::decay(double factor) {
    if (!(factor > 0.0 && factor < 1.0)) return;
    spam_samples_ = static_cast<std::size_t>(std::floor(spam_samples_ * factor));
    ham_samples_ = static_cast<std::size_t>(std::floor(ham_samples_ * factor));
    for (auto it = words_.begin(); it != words_.end();) {
        it->second.spam = static_cast<std::size_t>(std::floor(it->second.spam * factor));
        it->second.ham = static_cast<std::size_t>(std::floor(it->second.ham * factor));
        if (it->second.spam == 0 && it->second.ham == 0) it = words_.erase(it);
        else ++it;
    }
}

double BayesianModel::spam_probability(const std::string& text) const {
    if (spam_samples_ + ham_samples_ == 0) return 0.0;
    const double prior = (static_cast<double>(spam_samples_) + 1.0) /
        (static_cast<double>(spam_samples_ + ham_samples_) + 2.0);
    double log_spam = std::log(prior);
    double log_ham = std::log(1.0 - prior);
    std::unordered_set<std::string> unique;
    for (const auto& word : tokenize(text)) unique.insert(word);
    for (const auto& word : unique) {
        const auto it = words_.find(word);
        const double s = it == words_.end() ? 0.0 : static_cast<double>(it->second.spam);
        const double h = it == words_.end() ? 0.0 : static_cast<double>(it->second.ham);
        const double p_s = (s + 1.0) / (static_cast<double>(spam_samples_) + 2.0);
        const double p_h = (h + 1.0) / (static_cast<double>(ham_samples_) + 2.0);
        log_spam += std::log(p_s);
        log_ham += std::log(p_h);
    }
    const double delta = std::clamp(log_ham - log_spam, -40.0, 40.0);
    return 1.0 / (1.0 + std::exp(delta));
}

Filter::Filter(Settings settings) : settings_(settings) {}

Result Filter::classify(const Message& m, const BayesianModel* model) const {
    Result r;
    const auto text = combined_text(m);

    if (settings_.enable_authentication_rules) {
        if (contains(m.spf_result, "fail")) add(r, "auth.spf_fail", 25, "SPF認証がfail");
        if (contains(m.dkim_result, "fail")) add(r, "auth.dkim_fail", 20, "DKIM署名検証がfail");
        if (contains(m.dmarc_result, "fail")) add(r, "auth.dmarc_fail", 25, "DMARC認証がfail");
    }

    if (!m.from.empty() && !m.return_path.empty()) {
        const auto from = lower(m.from);
        const auto path = lower(m.return_path);
        const auto at1 = from.rfind('@');
        const auto at2 = path.rfind('@');
        if (at1 != std::string::npos && at2 != std::string::npos &&
            from.substr(at1 + 1) != path.substr(at2 + 1))
            add(r, "header.return_path_mismatch", 10, "FromとReturn-Pathのドメインが不一致");
    }

    if (contains(text, "パスワードを確認") || contains(text, "アカウントを停止") ||
        contains(text, "至急ご確認") || contains(text, "今すぐログイン") ||
        contains(text, "verify your account") || contains(text, "password expires"))
        add(r, "content.credential_lure", 15, "認証情報を急がせる表現を検出");

    if (settings_.enable_url_rules) {
        if (std::regex_search(text, std::regex(R"(https?://(?:\d{1,3}\.){3}\d{1,3})", std::regex::icase)))
            add(r, "url.ip_literal", 20, "IPアドレスを直接指定したURL");
        if (contains(text, "xn--"))
            add(r, "url.punycode", 10, "Punycodeを含むURLまたはドメイン");
    }

    if (model) {
        r.bayes_probability = model->spam_probability(text);
        if (model->spam_samples() >= 5 && model->ham_samples() >= 5) {
            const int bayes_score = static_cast<int>(std::lround(r.bayes_probability * 40.0));
            if (bayes_score > 0) add(r, "bayes.probability", bayes_score, "学習モデルによる迷惑メール確率");
        }
    }

    r.score = std::clamp(r.score, 0, 100);
    if (r.score >= settings_.spam_threshold) r.verdict = Verdict::Spam;
    else if (r.score >= settings_.review_threshold) r.verdict = Verdict::Review;
    else r.verdict = Verdict::Ham;
    return r;
}

} // namespace beckyas
