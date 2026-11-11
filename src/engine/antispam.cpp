#include "antispam.hpp"
#include "tokenizer.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <regex>
#include <unordered_set>
#include <unordered_map>

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
std::string trim_copy(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}
std::string extract_from_domain(const std::string& from) {
    std::string address = from;
    const auto left = address.find('<');
    const auto right = address.find('>', left == std::string::npos ? 0 : left + 1);
    if (left != std::string::npos && right != std::string::npos && right > left)
        address = address.substr(left + 1, right - left - 1);
    const auto at = address.rfind('@');
    if (at == std::string::npos) return {};
    return lower(trim_copy(address.substr(at + 1)));
}
std::string compact_ascii(const std::string& value) {
    std::string out;
    for (unsigned char c : lower(value)) {
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
            out.push_back(static_cast<char>(c));
    }
    return out;
}
std::size_t edit_distance(const std::string& a, const std::string& b) {
    std::vector<std::size_t> previous(b.size() + 1), current(b.size() + 1);
    for (std::size_t j = 0; j <= b.size(); ++j) previous[j] = j;
    for (std::size_t i = 1; i <= a.size(); ++i) {
        current[0] = i;
        for (std::size_t j = 1; j <= b.size(); ++j) {
            current[j] = std::min({previous[j] + 1, current[j - 1] + 1,
                previous[j - 1] + (a[i - 1] == b[j - 1] ? 0u : 1u)});
        }
        previous.swap(current);
    }
    return previous[b.size()];
}
bool looks_like_brand_domain(const std::string& host, const std::vector<std::string>& aliases) {
    std::vector<std::string> labels;
    std::size_t start = 0;
    while (start <= host.size()) {
        const auto end = host.find('.', start);
        const auto label = compact_ascii(host.substr(start,
            end == std::string::npos ? end : end - start));
        if (!label.empty()) labels.push_back(label);
        if (end == std::string::npos) break;
        start = end + 1;
    }
    for (const auto& alias : aliases) {
        const auto key = compact_ascii(alias);
        if (key.size() < 6) continue;
        for (const auto& label : labels) {
            if (label.find(key) != std::string::npos) return true;
            if (label.size() >= 6 && label.size() <= 64 && key.size() <= 64 &&
                edit_distance(label, key) <= 2) return true;
        }
    }
    return false;
}
bool domain_matches(const std::string& host, const std::string& allowed) {
    const auto h = lower(host);
    const auto a = lower(allowed);
    return !a.empty() && (h == a ||
        (h.size() > a.size() && h.compare(h.size() - a.size(), a.size(), a) == 0 &&
         h[h.size() - a.size() - 1] == '.'));
}
std::vector<std::string> extract_url_hosts(const std::string& text) {
    static const std::regex url_regex(
        R"((?:https?://|www\.)([^\s/<>\"'\)\]]+))", std::regex::icase);
    std::vector<std::string> hosts;
    for (std::sregex_iterator it(text.begin(), text.end(), url_regex), end; it != end; ++it) {
        auto host = lower((*it)[1].str());
        while (!host.empty() && (host.back() == '.' || host.back() == ',' ||
               host.back() == ';' || host.back() == ':')) host.pop_back();
        if (!host.empty()) hosts.push_back(std::move(host));
    }
    return hosts;
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

int capped_family_score(const std::vector<Finding>& findings, const std::string& family,
                        int cap, std::size_t* symbol_count) {
    std::unordered_map<std::string, int> unique_symbols;
    const std::string prefix = family + ".";
    for (const auto& finding : findings) {
        if (finding.rule.compare(0, prefix.size(), prefix) != 0) continue;
        auto& value = unique_symbols[finding.rule];
        value = std::max(value, finding.score);
    }
    if (symbol_count) *symbol_count += unique_symbols.size();
    int total = 0;
    for (const auto& item : unique_symbols) total += std::max(0, item.second);
    return std::min(cap, total);
}

void calculate_symbol_comparison(Result& result, const Settings& settings) {
    auto& comparison = result.symbol_comparison;
    comparison.authentication_score =
        capped_family_score(result.findings, "auth", 30, &comparison.symbol_count);
    comparison.header_score =
        capped_family_score(result.findings, "header", 10, &comparison.symbol_count);
    comparison.brand_score =
        capped_family_score(result.findings, "brand", 35, &comparison.symbol_count);
    comparison.content_score =
        capped_family_score(result.findings, "content", 25, &comparison.symbol_count);
    comparison.url_score =
        capped_family_score(result.findings, "url", 20, &comparison.symbol_count);

    // Exclude the active presence-only Bayes score. This bounded contribution
    // is diagnostic only and rewards positive evidence above the learned prior.
    if (settings.enable_bayes_comparison &&
        result.bayes_comparison.correlation_adjusted_features > 0) {
        // Score the evidence lift, not the posterior log-odds. A minority Spam
        // corpus can have a negative prior log-odds even when this message's
        // learned features strongly favor Spam over Ham.
        const double positive_evidence = std::max(
            0.0, result.bayes_comparison.correlation_adjusted_evidence_log_odds);
        comparison.bayes_score = std::min(20,
            static_cast<int>(positive_evidence * 6.0 + 0.5));
    }
    comparison.score = std::clamp(
        comparison.authentication_score + comparison.header_score +
        comparison.brand_score + comparison.content_score +
        comparison.url_score + comparison.bayes_score, 0, 100);
    if (comparison.score >= settings.spam_threshold)
        comparison.verdict = Verdict::Spam;
    else if (comparison.score >= settings.review_threshold)
        comparison.verdict = Verdict::Review;
    else
        comparison.verdict = Verdict::Ham;
}
void calculate_symbol_experiment(Result& result, const Settings& settings) {
    auto& experiment = result.symbol_experiment;
    std::unordered_map<std::string, int> content_symbols;
    std::unordered_map<std::string, int> url_symbols;
    for (const auto& finding : result.findings) {
        double multiplier = 1.0;
        if (finding.rule == "content.generic_lure_url") multiplier = 1.35;
        else if (finding.rule.compare(0, 8, "content.") == 0) multiplier = 1.25;
        else if (finding.rule == "url.ip_literal") multiplier = 1.50;
        else if (finding.rule == "url.multiple") multiplier = 1.25;
        if (finding.rule.compare(0, 8, "content.") == 0) {
            auto& value = content_symbols[finding.rule];
            value = std::max(value, static_cast<int>(std::lround(finding.score * multiplier)));
        } else if (finding.rule.compare(0, 4, "url.") == 0) {
            auto& value = url_symbols[finding.rule];
            value = std::max(value, static_cast<int>(std::lround(finding.score * multiplier)));
        }
    }
    for (const auto& item : content_symbols) experiment.content_score += std::max(0, item.second);
    for (const auto& item : url_symbols) experiment.url_score += std::max(0, item.second);
    experiment.content_score = std::min(35, experiment.content_score);
    experiment.url_score = std::min(25, experiment.url_score);
    if (settings.enable_bayes_comparison &&
        result.bayes_comparison.correlation_adjusted_features > 0) {
        const double positive_evidence = std::max(
            0.0, result.bayes_comparison.correlation_adjusted_evidence_log_odds);
        experiment.bayes_score = std::min(30,
            static_cast<int>(positive_evidence * 13.0 + 0.5));
    }
    experiment.score = std::clamp(
        result.symbol_comparison.authentication_score +
        result.symbol_comparison.header_score +
        result.symbol_comparison.brand_score + experiment.content_score +
        experiment.url_score + experiment.bayes_score, 0, 100);
    if (experiment.score >= settings.spam_threshold)
        experiment.verdict = Verdict::Spam;
    else if (experiment.score >= settings.review_threshold)
        experiment.verdict = Verdict::Review;
    else
        experiment.verdict = Verdict::Ham;
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

double BayesianModel::spam_probability(const std::string& text,
                                         BayesDiagnostics* diagnostics) const {
    if (diagnostics) *diagnostics = {};
    if (spam_samples_ + ham_samples_ == 0) return 0.0;
    const double prior = (static_cast<double>(spam_samples_) + 1.0) /
        (static_cast<double>(spam_samples_ + ham_samples_) + 2.0);
    double log_spam = std::log(prior);
    double log_ham = std::log(1.0 - prior);
    std::unordered_set<std::string> unique;
    for (const auto& word : tokenize(text)) unique.insert(word);
    if (diagnostics) diagnostics->total_tokens = unique.size();

    for (const auto& word : unique) {
        const auto it = words_.find(word);
        // A token absent from both training classes is unknown, not evidence
        // for the smaller class. Applying class-specific denominators to
        // (0,0) counts incorrectly biases every unseen token toward Spam when
        // ham_samples_ is larger than spam_samples_.
        if (it == words_.end()) {
            if (diagnostics) ++diagnostics->unknown_tokens;
            continue;
        }

        if (diagnostics) ++diagnostics->known_tokens;
        const double s = static_cast<double>(it->second.spam);
        const double h = static_cast<double>(it->second.ham);
        const double p_s = (s + 1.0) / (static_cast<double>(spam_samples_) + 2.0);
        const double p_h = (h + 1.0) / (static_cast<double>(ham_samples_) + 2.0);
        const double contribution = std::log(p_s) - std::log(p_h);
        if (diagnostics) {
            if (contribution > 1e-12) ++diagnostics->spam_evidence_tokens;
            else if (contribution < -1e-12) ++diagnostics->ham_evidence_tokens;
        }
        log_spam += std::log(p_s);
        log_ham += std::log(p_h);
    }

    const double log_odds = log_spam - log_ham;
    if (diagnostics) diagnostics->log_odds = log_odds;
    const double delta = std::clamp(-log_odds, -40.0, 40.0);
    return 1.0 / (1.0 + std::exp(delta));
}


BayesComparison BayesianModel::compare_probabilities(const std::string& text) const {
    BayesComparison result;
    result.presence_probability = spam_probability(text, nullptr);
    if (spam_samples_ + ham_samples_ == 0) return result;

    const double prior = (static_cast<double>(spam_samples_) + 1.0) /
        (static_cast<double>(spam_samples_ + ham_samples_) + 2.0);
    const double prior_log_odds = std::log(prior / (1.0 - prior));
    double present_log_odds = 0.0;
    double absent_log_odds = 0.0;
    std::unordered_set<std::string> present;
    for (const auto& token : tokenize(text)) present.insert(token);

    // Bernoulli NB evaluates both presence and absence for each retained
    // vocabulary feature. Keep the two evidence components separate: with a
    // large sparse Japanese vocabulary, correlated absent features can
    // dominate the raw Bernoulli score and make its posterior uninformative.
    result.vocabulary_features = words_.size();
    for (const auto& entry : words_) {
        const double p_spam = (static_cast<double>(entry.second.spam) + 1.0) /
            (static_cast<double>(spam_samples_) + 2.0);
        const double p_ham = (static_cast<double>(entry.second.ham) + 1.0) /
            (static_cast<double>(ham_samples_) + 2.0);
        if (present.find(entry.first) != present.end()) {
            present_log_odds += std::log(p_spam) - std::log(p_ham);
            ++result.bernoulli_present_features;
        } else {
            absent_log_odds += std::log1p(-p_spam) - std::log1p(-p_ham);
        }
    }
    result.bernoulli_absent_features =
        result.vocabulary_features - result.bernoulli_present_features;
    result.bernoulli_present_log_odds = present_log_odds;
    result.bernoulli_absent_log_odds = absent_log_odds;
    result.bernoulli_log_odds =
        prior_log_odds + present_log_odds + absent_log_odds;
    const double delta = std::clamp(-result.bernoulli_log_odds, -40.0, 40.0);
    result.bernoulli_probability = 1.0 / (1.0 + std::exp(delta));
    BayesDiagnostics diagnostics;
    spam_probability(text, &diagnostics);
    result.presence_log_odds = diagnostics.log_odds;

    // Correlation-aware presence comparison:
    // - smooth each class toward the same corpus-wide token rate, avoiding
    //   class-size artifacts for tokens seen in only one class;
    // - average token evidence instead of summing every overlapping Japanese
    //   bigram as if it were statistically independent.
    const double total_samples = static_cast<double>(spam_samples_ + ham_samples_);
    const double prior_log_odds = std::log(prior / (1.0 - prior));
    constexpr double smoothing_strength = 5.0;
    double evidence_sum = 0.0;
    std::size_t known_features = 0;
    for (const auto& token : present) {
        const auto it = words_.find(token);
        if (it == words_.end()) continue;
        const double spam_docs = static_cast<double>(it->second.spam);
        const double ham_docs = static_cast<double>(it->second.ham);
        const double corpus_rate = (spam_docs + ham_docs + 1.0) /
            (total_samples + 2.0);
        const double p_spam = (spam_docs + smoothing_strength * corpus_rate) /
            (static_cast<double>(spam_samples_) + smoothing_strength);
        const double p_ham = (ham_docs + smoothing_strength * corpus_rate) /
            (static_cast<double>(ham_samples_) + smoothing_strength);
        evidence_sum += std::log(p_spam) - std::log(p_ham);
        ++known_features;
    }
    result.correlation_adjusted_features = known_features;
    result.correlation_adjustment_scale = known_features == 0
        ? 0.0 : 1.0 / (static_cast<double>(known_features) + smoothing_strength);
    result.correlation_adjusted_evidence_log_odds =
        evidence_sum * result.correlation_adjustment_scale;
    result.correlation_adjusted_log_odds = prior_log_odds +
        result.correlation_adjusted_evidence_log_odds;
    const double correlation_delta =
        std::clamp(-result.correlation_adjusted_log_odds, -40.0, 40.0);
    result.correlation_adjusted_probability = 1.0 / (1.0 + std::exp(correlation_delta));
    return result;
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

    // Brand impersonation: compare a matched brand in Subject / From display name
    // with the actual From domain. Allowed domains are exact or proper subdomains.
    r.brand_rules_checked = settings_.brand_rules.size();
    if (!settings_.brand_rules.empty()) {
        const auto from_domain = extract_from_domain(m.from);
        r.brand_from_domain_present = !from_domain.empty();
        const auto angle_left = m.from.find('<');
        const auto display_name = angle_left == std::string::npos
            ? std::string{} : trim_copy(m.from.substr(0, angle_left));
        const auto url_hosts = extract_url_hosts(m.body);
        for (const auto& brand : settings_.brand_rules) {
            bool subject_match = false;
            bool display_match = false;
            for (const auto& alias : brand.aliases) {
                if (alias.empty()) continue;
                subject_match = subject_match || contains(m.subject, alias);
                display_match = display_match || contains(display_name, alias);
            }
            if (!subject_match && !display_match) continue;
            r.brand_rule_matched = true;
            r.brand_subject_match = subject_match;
            r.brand_display_match = display_match;
            r.brand_url_hosts_checked = url_hosts.size();
            const bool from_allowed = std::any_of(
                brand.allowed_domains.begin(), brand.allowed_domains.end(),
                [&](const std::string& domain) { return domain_matches(from_domain, domain); });
            r.brand_from_allowed = from_allowed;
            if (!from_allowed) {
                const int mismatch_score = (subject_match && display_match) ? 35 : 30;
                add(r, "brand.domain_mismatch", mismatch_score,
                    "ブランド名とFromドメインが一致しない");
            }
            if (!from_allowed && looks_like_brand_domain(from_domain, brand.aliases))
                add(r, "brand.lookalike_domain", 15,
                    "Fromドメインがブランド名に類似している");
            const bool url_mismatch = !url_hosts.empty() &&
                std::any_of(url_hosts.begin(), url_hosts.end(), [&](const std::string& host) {
                    return std::none_of(brand.allowed_domains.begin(), brand.allowed_domains.end(),
                        [&](const std::string& domain) { return domain_matches(host, domain); });
                });
            r.brand_url_domain_mismatch = url_mismatch;
            if (url_mismatch)
                add(r, "brand.url_domain_mismatch", 15,
                    "ブランド名に関連するメール内URLのドメインが許可ドメインと一致しない");
            break;
        }
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
        r.bayes_probability = model->spam_probability(text, &r.bayes_diagnostics);
        if (settings_.enable_bayes_comparison)
            r.bayes_comparison = model->compare_probabilities(text);
        if (model->spam_samples() >= 5 && model->ham_samples() >= 5) {
            const int bayes_score = static_cast<int>(std::lround(r.bayes_probability * 40.0));
            if (bayes_score > 0) add(r, "bayes.probability", bayes_score, "学習モデルによる迷惑メール確率");
        }
    }

    r.score = std::clamp(r.score, 0, 100);
    if (r.score >= settings_.spam_threshold) r.verdict = Verdict::Spam;
    else if (r.score >= settings_.review_threshold) r.verdict = Verdict::Review;
    else r.verdict = Verdict::Ham;

    // Comparison-only Rspamd-style aggregation; active score/verdict stay intact.
    if (settings_.enable_symbol_comparison) {
        calculate_symbol_comparison(r, settings_);
        calculate_symbol_experiment(r, settings_);
    }
    return r;
}

} // namespace beckyas
