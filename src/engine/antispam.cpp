#include "antispam.hpp"
#include "tokenizer.hpp"

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
bool contains_any(const std::string& haystack, const std::vector<std::string>& needles) {
    return std::any_of(needles.begin(), needles.end(), [&](const std::string& needle) {
        return contains(haystack, needle);
    });
}
std::size_t count_url_markers(const std::string& text) {
    static const std::regex url_pattern(R"((https?://|www\.))", std::regex::icase);
    return static_cast<std::size_t>(std::distance(
        std::sregex_iterator(text.begin(), text.end(), url_pattern),
        std::sregex_iterator()));
}
std::string combined_text(const Message& m) {
    return classifier_text(m);
}
void add(Result& r, const char* id, int score, const char* reason) {
    r.score += score;
    r.findings.push_back({id, score, reason});
}
} // namespace

std::string classifier_text(const Message& message) {
    // Avoid tokenizing sender addresses; use the same subject/header/body text for training and scoring.
    return message.subject + "\n" + message.headers + "\n" + message.body;
}

BayesianModel::BayesianModel(std::size_t max_vocabulary)
    : max_vocabulary_(std::max<std::size_t>(1, max_vocabulary)) {}

void BayesianModel::restore(std::size_t spam_samples, std::size_t ham_samples,
                            const std::vector<TokenCount>& token_counts) {
    words_.clear();
    spam_samples_ = spam_samples;
    ham_samples_ = ham_samples;
    for (const auto& item : token_counts) {
        if (item.token.empty() || (item.spam_docs == 0 && item.ham_docs == 0)) continue;
        words_[item.token] = Counts{item.spam_docs, item.ham_docs};
    }
    if (words_.size() > max_vocabulary_) compact(max_vocabulary_);
}

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

    if (settings_.enable_authentication_rules && m.trusted_authentication_results) {
        if (contains(m.spf_result, "fail")) add(r, "auth.spf_fail", 25, "SPF認証がfail");
        if (contains(m.dkim_result, "fail")) add(r, "auth.dkim_fail", 20, "DKIM署名検証がfail");
        if (contains(m.dmarc_result, "fail")) add(r, "auth.dmarc_fail", 25, "DMARC認証がfail");
    }

    if (m.trusted_return_path && !m.from.empty() && !m.return_path.empty()) {
        const auto from = lower(m.from);
        const auto path = lower(m.return_path);
        const auto at1 = from.rfind('@');
        const auto at2 = path.rfind('@');
        if (at1 != std::string::npos && at2 != std::string::npos &&
            from.substr(at1 + 1) != path.substr(at2 + 1))
            add(r, "header.return_path_mismatch", 10, "FromとReturn-Pathのドメインが不一致");
    }

    const bool account_lure = contains_any(text, {
        "アカウントを停止", "アカウントが停止", "アカウントの利用制限",
        "本人確認が必要", "本人確認を行", "不正アクセスを検知",
        "パスワードを確認", "パスワードを再設定", "今すぐログイン",
        "verify your account", "password expires", "account has been suspended",
        "unusual sign-in activity"
    });
    const bool payment_lure = contains_any(text, {
        "未払い料金", "お支払い方法", "決済に失敗", "支払いを確認",
        "請求内容を確認", "カード情報を更新", "payment failed",
        "outstanding payment", "billing information"
    });
    const bool delivery_lure = contains_any(text, {
        "再配達を依頼", "お届け先住所", "配送先住所に不備",
        "配達に伺いました", "配送状況を確認", "荷物をお届け",
        "redelivery", "delivery address"
    });
    const bool urgency_lure = contains_any(text, {
        "至急ご確認", "至急対応", "本日中に", "24時間以内",
        "期限までに", "まもなく無効", "直ちに確認", "immediately",
        "within 24 hours", "final warning"
    });

    if (account_lure)
        add(r, "content.account_lure", 10, "アカウント確認・停止を促す表現");
    if (payment_lure)
        add(r, "content.payment_lure", 10, "支払い・決済情報の確認を促す表現");
    if (delivery_lure)
        add(r, "content.delivery_lure", 10, "配送・再配達の確認を促す表現");
    if (urgency_lure)
        add(r, "content.urgency", 5, "期限や緊急性を強調する表現");

    const auto url_count = count_url_markers(text);
    const bool action_lure = account_lure || payment_lure || delivery_lure;
    if (url_count > 0 && action_lure)
        add(r, "content.lure_with_url", 10, "誘導表現とURLが同時に存在");

    // Catch common Japanese phishing wording variants without treating a
    // generic "確認" or "ログイン" phrase as suspicious on its own.
    const bool account_term = contains_any(text, {
        "アカウント", "ログイン", "サインイン", "パスワード", "本人確認",
        "account", "sign in", "password"
    });
    const bool account_action = contains_any(text, {
        "確認", "更新", "停止", "制限", "解除", "再設定", "有効期限",
        "verify", "update", "suspend", "reset"
    });
    const bool payment_term = contains_any(text, {
        "支払い", "お支払い", "決済", "請求", "カード情報",
        "payment", "billing", "card"
    });
    const bool payment_action = contains_any(text, {
        "確認", "更新", "失敗", "未払い", "期限", "update", "failed", "overdue"
    });
    const bool generic_lure = (account_term && account_action) ||
                              (payment_term && payment_action);
    const bool call_to_action = contains_any(text, {
        "こちらから", "下記リンク", "リンクより", "クリックしてください",
        "ご確認ください", "アクセスしてください", "click here", "follow this link"
    });
    if (url_count > 0 && generic_lure && !action_lure)
        add(r, "content.generic_lure_url", 22, "アカウント・支払い操作を促す表現とURL");
    if (url_count > 0 && call_to_action && !action_lure)
        add(r, "content.call_to_action_url", 8, "操作を促す文言とURL");
    if (settings_.enable_url_rules) {
        if (std::regex_search(text, std::regex(R"(https?://(?:\d{1,3}\.){3}\d{1,3})", std::regex::icase)))
            add(r, "url.ip_literal", 20, "IPアドレスを直接指定したURL");
        if (contains(text, "xn--"))
            add(r, "url.punycode", 10, "Punycodeを含むURLまたはドメイン");
        if (contains_any(text, {
            "bit.ly/", "tinyurl.com/", "t.co/", "is.gd/", "cutt.ly/",
            "rebrand.ly/", "shorturl.at/"
        }))
            add(r, "url.shortener", 8, "短縮URLサービスへのリンク");
        if (url_count >= 4)
            add(r, "url.multiple", 8, "複数のURLを検出");
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
