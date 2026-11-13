#include "antispam.hpp"
#include "sqlite_store.hpp"
#include "message_parser.hpp"
#include "sha256.hpp"
#include "tokenizer.hpp"
#include "mail_pipeline.hpp"

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <iostream>
#include <cmath>
#include <sqlite3.h>

using namespace beckyas;

int main() {
    std::string error;

    // SHA-256 known-answer tests (FIPS 180-4).
    assert(sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert(sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // UTF-8 Japanese fallback tokenizer: bigrams, katakana compounds and ASCII.
    const auto jp_tokens = tokenize("無料キャンペーンに当選しました Phishing123 20261106");
    const auto has_token = [&jp_tokens](const std::string& token) {
        return std::find(jp_tokens.begin(), jp_tokens.end(), token) != jp_tokens.end();
    };
    assert(has_token("無料"));
    assert(has_token("キャンペーン"));
    assert(has_token("当選"));
    assert(has_token("phishing123"));
    assert(!has_token("20261106")); // pure numeric IDs are ignored
    const std::string oversized_token_input(1024 * 1024 + 128, 'a');
    assert(tokenize(oversized_token_input).size() <= 1); // input scan is capped at 1 MiB

    // Header unfolding, RFC 2047 Q decoding, MIME multipart and transfer decoding.
    const std::string raw_mail =
        "From: Example Sender <sender@example.jp>\r\n"
        "Return-Path: <bounce@example.jp>\r\n"
        "Subject: =?UTF-8?Q?Hello=20World?=\r\n"
        "List-Unsubscribe: <https://example.jp/unsubscribe>\r\n"
        "X-Long: first\r\n\tsecond\r\n"
        "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=fail\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"mix-boundary\"\r\n"
        "\r\n"
        "--mix-boundary\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "Content-Transfer-Encoding: quoted-printable\r\n"
        "\r\n"
        "Hello=20mail=21\r\n"
        "--mix-boundary\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment; filename=\"sample.bin\"\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "AAECAwQ=\r\n"
        "--mix-boundary--\r\n";
    MessageParser parser;
    ParsedMail parsed;
    assert(parser.parse(raw_mail, parsed, &error));
    assert(parsed.message.from.find("sender@example.jp") != std::string::npos);
    assert(parsed.message.return_path.find("bounce@example.jp") != std::string::npos);
    assert(parsed.message.subject == "Hello World");
    assert(parsed.message.body.find("Hello mail!") != std::string::npos);
    assert(parsed.authentication_results.size() == 1);
    assert(parsed.authentication_results[0].find("spf=pass") != std::string::npos);
    // Untrusted authentication headers must not influence classifier inputs.
    assert(!parsed.message.trusted_authentication_results);
    assert(!parsed.message.trusted_return_path);
    assert(parsed.message.spf_result.empty());
    assert(parsed.message.dkim_result.empty());
    assert(parsed.message.dmarc_result.empty());
    assert(parsed.headers.size() >= 7);
    assert(parsed.headers[4].name == "x-long");
    assert(parsed.headers[4].value == "first second");
    assert(parsed.attachments.size() == 1);
    assert(parsed.attachments[0].filename == "sample.bin");
    assert(parsed.mime_parts == 3);
    assert(sha256_hex(raw_mail).size() == 64);
    const auto parsed_classifier_text = classifier_text(parsed.message);
    assert(parsed_classifier_text.find("Hello World") != std::string::npos);
    assert(parsed_classifier_text.find("Hello mail!") != std::string::npos);
    assert(parsed_classifier_text.find("sender@example.jp") == std::string::npos); // no sender address in Bayes corpus
    assert(parsed.message.headers.find("https://example.jp/unsubscribe") != std::string::npos);
    assert(parsed.message.headers.find("spf=pass") == std::string::npos); // untrusted auth header excluded
    assert(parsed.message.headers.find("sender@example.jp") == std::string::npos);

    Settings brand_settings;
    brand_settings.brand_rules.push_back({
        {"American Express", "AmericanExpress", "アメックス"},
        {"americanexpress.com"}
    });
    Filter brand_filter(brand_settings);
    Message amex_spoof;
    amex_spoof.from = "\"AE ID\" <AmericanExpresst@stpvpv.asia>";
    amex_spoof.subject = "【American Express】次回のお支払い金額、変更期限をご確認ください";
    amex_spoof.body = "お支払い内容をご確認ください https://stpvpv.asia/login";
    const auto amex_result = brand_filter.classify(amex_spoof);
    assert(amex_result.verdict == Verdict::Spam);
    assert(amex_result.brand_rules_checked == 1);
    assert(amex_result.brand_rule_matched);
    assert(amex_result.brand_subject_match);
    assert(amex_result.brand_display_match);
    assert(amex_result.brand_from_domain_present);
    assert(!amex_result.brand_from_allowed);
    assert(amex_result.brand_url_hosts_checked == 1);
    assert(amex_result.brand_url_domain_mismatch);
    assert(std::any_of(amex_result.findings.begin(), amex_result.findings.end(),
        [](const Finding& finding) { return finding.rule == "brand.domain_mismatch"; }));
    assert(std::any_of(amex_result.findings.begin(), amex_result.findings.end(),
        [](const Finding& finding) { return finding.rule == "brand.url_domain_mismatch"; }));

    Message amex_lookalike;
    amex_lookalike.from = "notice@americanexpresst.asia";
    amex_lookalike.subject = "American Express お支払い確認";
    const auto lookalike_result = brand_filter.classify(amex_lookalike);
    assert(std::any_of(lookalike_result.findings.begin(), lookalike_result.findings.end(),
        [](const Finding& finding) { return finding.rule == "brand.lookalike_domain"; }));

    Message amex_legitimate;
    amex_legitimate.from = "American Express <notice@americanexpress.com>";
    amex_legitimate.subject = "American Express ご利用明細";
    const auto amex_legitimate_result = brand_filter.classify(amex_legitimate);
    assert(amex_legitimate_result.verdict == Verdict::Ham);
    assert(amex_legitimate_result.brand_rules_checked == 1);
    assert(amex_legitimate_result.brand_rule_matched);
    assert(amex_legitimate_result.brand_subject_match);
    assert(amex_legitimate_result.brand_display_match);
    assert(amex_legitimate_result.brand_from_domain_present);
    assert(amex_legitimate_result.brand_from_allowed);
    assert(!amex_legitimate_result.brand_url_domain_mismatch);

    Filter filter;
    // Common Japanese account-action wording plus a link should be escalated
    // to Review, but a generic login word without a link must remain Ham.
    Message generic_phishing;
    generic_phishing.subject = "アカウント情報の確認";
    generic_phishing.body = "アカウント情報を更新してください。こちらから確認できます https://example.invalid/login";
    const auto generic_result = filter.classify(generic_phishing);
    assert(generic_result.score >= 30);
    assert(generic_result.verdict == Verdict::Review);
    Message ordinary_login_notice;
    ordinary_login_notice.subject = "社内システムのログイン方法";
    ordinary_login_notice.body = "ログイン方法を案内します。";
    assert(filter.classify(ordinary_login_notice).verdict == Verdict::Ham);

    // www. URL markers must be recognized (the previous expression escaped
    // the backslash rather than the dot).
    Message multiple_www_urls;
    multiple_www_urls.body =
        "www.example1.invalid www.example2.invalid www.example3.invalid www.example4.invalid";
    const auto multiple_url_result = filter.classify(multiple_www_urls);
    assert(std::any_of(multiple_url_result.findings.begin(), multiple_url_result.findings.end(),
        [](const Finding& finding) { return finding.rule == "url.multiple"; }));


    ParseLimits tiny_limits;
    tiny_limits.max_message_bytes = 8;
    MessageParser tiny_parser(tiny_limits);
    ParsedMail rejected;
    assert(!tiny_parser.parse(raw_mail, rejected, &error));
#ifdef _WIN32
    // Shift_JIS header and body are converted to UTF-8 on the target Windows platform.
    std::string sjis_mail =
        "Subject: =?Shift_JIS?B?k/qWe4zq?=\r\n"
        "Content-Type: text/plain; charset=Shift_JIS\r\n"
        "\r\n";
    sjis_mail.append("\x93\xfa\x96\x7b\x8c\xea", 6);
    ParsedMail sjis_parsed;
    assert(parser.parse(sjis_mail, sjis_parsed, &error));
    assert(sjis_parsed.message.subject == "日本語");
    assert(sjis_parsed.message.body == "日本語");
#endif


    Message clean;
    clean.from = "staff@example.jp";
    clean.return_path = "staff@example.jp";
    clean.subject = "会議資料を送付します";
    clean.body = "明日の会議資料を添付します。";
    assert(filter.classify(clean).verdict == Verdict::Ham);

    Message suspicious;
    suspicious.from = "notice@fake.example";
    suspicious.return_path = "bounce@other.example";
    suspicious.subject = "至急ご確認ください";
    suspicious.body = "アカウントを停止します。今すぐログインしてください。"
                      " https://192.0.2.10/login";
    suspicious.trusted_return_path = true;
    suspicious.trusted_authentication_results = true;
    suspicious.spf_result = "fail";
    suspicious.dmarc_result = "fail";
    const auto result = filter.classify(suspicious);
    assert(result.score >= 60);
    assert(result.verdict == Verdict::Spam);

    // Rspamd-inspired symbol scoring is an offline comparison and must not
    // change the active classifier score or verdict.
    Settings legacy_symbol_settings;
    Settings candidate_symbol_settings;
    candidate_symbol_settings.enable_bayes_comparison = true;
    candidate_symbol_settings.enable_symbol_comparison = true;
    BrandRule candidate_brand;
    candidate_brand.aliases = {"Amazon"};
    candidate_brand.allowed_domains = {"amazon.co.jp"};
    candidate_symbol_settings.brand_rules.push_back(candidate_brand);
    legacy_symbol_settings.brand_rules.push_back(candidate_brand);
    Filter legacy_symbol_filter(legacy_symbol_settings);
    Filter candidate_symbol_filter(candidate_symbol_settings);
    BayesianModel symbol_model;
    for (int i = 0; i < 6; ++i) {
        symbol_model.train("無料 当選 賞金 アカウント 支払い", true);
        symbol_model.train("会議 議事録 業務 予定", false);
    }
    Message symbol_message;
    symbol_message.from = "Amazon <notice@fake.invalid>";
    symbol_message.return_path = "bounce@other.invalid";
    symbol_message.subject = "Amazon アカウントを停止";
    symbol_message.body =
        "アカウントを停止します。未払い料金のお支払い方法を確認してください。"
        "本日中に対応してください https://bad.invalid/a https://bad.invalid/b "
        "https://bad.invalid/c https://bad.invalid/d";
    symbol_message.trusted_return_path = true;
    symbol_message.trusted_authentication_results = true;
    symbol_message.spf_result = "fail";
    symbol_message.dkim_result = "fail";
    symbol_message.dmarc_result = "fail";
    const auto legacy_symbol_result =
        legacy_symbol_filter.classify(symbol_message, &symbol_model);
    const auto candidate_symbol_result =
        candidate_symbol_filter.classify(symbol_message, &symbol_model);
    assert(candidate_symbol_result.score == legacy_symbol_result.score);
    assert(candidate_symbol_result.verdict == legacy_symbol_result.verdict);
    assert(candidate_symbol_result.symbol_comparison.score > 0);
    assert(candidate_symbol_result.symbol_comparison.authentication_score <= 30);
    assert(candidate_symbol_result.symbol_comparison.header_score <= 10);
    assert(candidate_symbol_result.symbol_comparison.brand_score <= 35);
    assert(candidate_symbol_result.symbol_comparison.content_score <= 25);
    assert(candidate_symbol_result.symbol_comparison.url_score <= 20);
    assert(candidate_symbol_result.symbol_comparison.bayes_score <= 20);
    assert(candidate_symbol_result.symbol_comparison.score <= 100);
    assert(candidate_symbol_result.symbol_comparison.verdict == Verdict::Spam);
    assert(candidate_symbol_result.symbol_experiment.score >=
           candidate_symbol_result.symbol_comparison.score);
    assert(candidate_symbol_result.symbol_experiment.content_score <= 35);
    assert(candidate_symbol_result.symbol_experiment.url_score <= 25);
    assert(candidate_symbol_result.symbol_experiment.bayes_score <= 30);
    assert(candidate_symbol_result.symbol_experiment.verdict == Verdict::Spam);

    BayesianModel model;
    for (int i = 0; i < 6; ++i) {
        model.train("当選 無料 賞金 今すぐ応募", true);
        model.train("会議 議事録 業務 予定", false);
    }
    assert(model.spam_probability("無料 賞金 当選") >
           model.spam_probability("会議 議事録"));

    // Unknown tokens must be neutral even when the training classes are imbalanced.
    BayesianModel imbalanced;
    for (int i = 0; i < 19; ++i)
        imbalanced.train("knownspamfeature", true);
    for (int i = 0; i < 131; ++i)
        imbalanced.train("knownhamfeature", false);
    const double prior_probability = imbalanced.spam_probability("");
    BayesDiagnostics unknown_diagnostics;
    const double unknown_probability =
        imbalanced.spam_probability("neverseenword anotherunknownword", &unknown_diagnostics);
    assert(std::abs(unknown_probability - prior_probability) < 1e-12);
    assert(unknown_diagnostics.total_tokens == 2);
    assert(unknown_diagnostics.known_tokens == 0);
    assert(unknown_diagnostics.unknown_tokens == 2);
    assert(unknown_diagnostics.spam_evidence_tokens == 0);
    assert(unknown_diagnostics.ham_evidence_tokens == 0);
    assert(std::abs(unknown_diagnostics.log_odds -
        std::log(prior_probability / (1.0 - prior_probability))) < 1e-12);
    assert(imbalanced.spam_probability("knownspamfeature") > prior_probability);
    assert(imbalanced.spam_probability("knownhamfeature") < prior_probability);

    // A Ham-only token seen in just one document must not become Spam evidence
    // solely because the Spam and Ham class denominators are different.
    BayesianModel singleton_ham;
    for (int i = 0; i < 19; ++i)
        singleton_ham.train("spam_class_background", true);
    singleton_ham.train("ham_singleton_feature", false);
    for (int i = 0; i < 130; ++i)
        singleton_ham.train("ham_class_background", false);
    const double singleton_prior = singleton_ham.spam_probability("");
    assert(singleton_ham.spam_probability("ham_singleton_feature") > singleton_prior);
    const auto singleton_ham_comparison =
        singleton_ham.compare_probabilities("ham_singleton_feature");
    assert(singleton_ham_comparison.correlation_adjusted_probability < singleton_prior);

    const auto comparison = imbalanced.compare_probabilities("knownspamfeature unknownfeature");
    assert(std::isfinite(comparison.presence_probability));
    assert(std::isfinite(comparison.bernoulli_probability));
    assert(comparison.vocabulary_features == imbalanced.vocabulary_size());
    assert(comparison.bernoulli_present_features == 1);
    assert(comparison.bernoulli_absent_features ==
           comparison.vocabulary_features - comparison.bernoulli_present_features);
    assert(std::abs(comparison.bernoulli_log_odds -
        (std::log(imbalanced.spam_probability("") /
                  (1.0 - imbalanced.spam_probability(""))) +
         comparison.bernoulli_present_log_odds +
         comparison.bernoulli_absent_log_odds)) < 1e-9);
    assert(std::abs(comparison.presence_probability -
        imbalanced.spam_probability("knownspamfeature unknownfeature")) < 1e-12);
    // Bernoulli scoring includes absent vocabulary features and may differ
    // from the presence-only baseline.
    assert(std::abs(comparison.bernoulli_probability -
        comparison.presence_probability) > 1e-9);
    assert(std::isfinite(comparison.correlation_adjusted_probability));
    assert(comparison.correlation_adjusted_features == 1);
    assert(comparison.correlation_adjustment_scale > 0.0);
    // The correlation-aware estimate is deliberately less extreme than the
    // raw presence model for a single learned feature.
    assert(comparison.correlation_adjusted_probability <
           comparison.presence_probability);

    // A token observed only in the larger Ham class must not become Spam
    // evidence merely because the class denominators differ.
    const double balanced_prior = imbalanced.spam_probability("");
    const auto ham_only_comparison =
        imbalanced.compare_probabilities("knownhamfeature");
    assert(ham_only_comparison.correlation_adjusted_probability < balanced_prior);
    assert(ham_only_comparison.correlation_adjusted_features == 1);

    const auto once = imbalanced.compare_probabilities("knownspamfeature");

    // A minority-class prior can keep posterior odds below zero even when
    // the observed feature itself strongly favors Spam. Preserve that lift
    // separately so the symbol comparison can award bounded evidence points.
    assert(once.correlation_adjusted_evidence_log_odds > 0.0);
    assert(once.correlation_adjusted_log_odds < 0.0);
    assert(std::abs(once.correlation_adjusted_log_odds -
        (std::log(balanced_prior / (1.0 - balanced_prior)) +
         once.correlation_adjusted_evidence_log_odds)) < 1e-12);
    Settings bayes_symbol_settings;
    bayes_symbol_settings.enable_bayes_comparison = true;
    bayes_symbol_settings.enable_symbol_comparison = true;
    Filter bayes_symbol_filter(bayes_symbol_settings);
    Message spam_feature_message;
    spam_feature_message.subject = "knownspamfeature";
    const auto bayes_symbol_result =
        bayes_symbol_filter.classify(spam_feature_message, &imbalanced);
    assert(bayes_symbol_result.symbol_comparison.bayes_score > 0);
    assert(bayes_symbol_result.symbol_comparison.bayes_score <= 20);
    assert(bayes_symbol_result.symbol_comparison.score ==
           bayes_symbol_result.symbol_comparison.bayes_score);

    // Repeating an identical message must not multiply evidence: the tokenizer
    // returns unique features and the adjusted estimate is deterministic.
    const auto repeated = imbalanced.compare_probabilities(
        "knownspamfeature knownspamfeature knownspamfeature");
    assert(std::abs(once.correlation_adjusted_probability -
        repeated.correlation_adjusted_probability) < 1e-12);

    BayesianModel bounded(3);
    bounded.train("alpha beta gamma", true);
    bounded.train("delta epsilon zeta", false);
    assert(bounded.vocabulary_size() <= 3);
    assert(bounded.max_vocabulary() == 3);
    const auto removed = bounded.compact(2, 1);
    assert(removed >= 1);
    assert(bounded.vocabulary_size() <= 2);

    const auto before_decay = model.spam_samples();
    model.decay(0.5);
    assert(model.spam_samples() <= before_decay);
    const auto unchanged = model.spam_samples();
    model.decay(1.0);
    assert(model.spam_samples() == unchanged);

    const auto temp = std::filesystem::temp_directory_path();
    const auto db_path = (temp / "becky_antispam_storage_test.sqlite3").string();
    const auto backup_path = (temp / "becky_antispam_storage_backup.sqlite3").string();
    std::filesystem::remove(db_path);
    std::filesystem::remove(db_path + "-wal");
    std::filesystem::remove(db_path + "-shm");
    std::filesystem::remove(backup_path);

    SqliteStore store(db_path);
    assert(store.open(&error));
    const std::string spam_hash(64, 'a');
    const std::string ham_hash(64, 'b');
    assert(store.train_once("invalid-hash", "ignored", true, &error) == TrainStatus::Error);
    assert(store.train_once(spam_hash, "free prize winner offer", true, &error) == TrainStatus::Trained);
    assert(store.train_once(spam_hash, "free prize winner offer", true, &error) == TrainStatus::Duplicate);
    assert(store.train_once(ham_hash, "meeting agenda project", false, &error) == TrainStatus::Trained);
    const std::string corrected_hash(64, 'c');
    assert(store.train_once(corrected_hash, "fraud offer", true, &error) == TrainStatus::Trained);
    assert(store.train_once(corrected_hash, "fraud offer", false, &error) == TrainStatus::Reclassified);
    assert(store.train_once(corrected_hash, "fraud offer", false, &error) == TrainStatus::Duplicate);

    BayesianModel restored;
    assert(store.load_model(restored, &error));
    assert(restored.spam_samples() == 1);
    assert(restored.ham_samples() == 2);
    assert(restored.spam_probability("free prize winner") >
           restored.spam_probability("meeting agenda"));

    StoreStats stats;
    assert(store.get_stats(stats, &error));
    assert(stats.spam_samples == 1 && stats.ham_samples == 2);
    assert(stats.training_receipts == 3);
    assert(stats.vocabulary_size >= 5);

    // Evaluation metrics retain the prediction made before the user confirms a label.
    const std::string eval_spam_hit(64, 'e');
    const std::string eval_spam_review(64, 'f');
    const std::string eval_spam_miss(64, 'g');
    const std::string eval_ham_false_positive(64, 'h');
    const std::string eval_ham_hit(64, 'i');
    const std::string eval_pending(64, 'j');
    assert(store.record_evaluation_prediction(eval_spam_hit, Verdict::Spam, 80, 0.99, 2, 5, &error, Verdict::Spam, 82));
    assert(store.complete_evaluation(eval_spam_hit, true, &error));
    assert(store.record_evaluation_prediction(eval_spam_review, Verdict::Review, 40, 0.80, 2, 5, &error, Verdict::Review, 35));
    assert(store.complete_evaluation(eval_spam_review, true, &error));
    assert(store.record_evaluation_prediction(eval_spam_miss, Verdict::Ham, 0, 0.01, 2, 5, &error, Verdict::Ham, 0));
    assert(store.complete_evaluation(eval_spam_miss, true, &error));
    assert(store.record_evaluation_prediction(eval_ham_false_positive, Verdict::Spam, 70, 0.95, 2, 5, &error, Verdict::Review, 40));
    assert(store.complete_evaluation(eval_ham_false_positive, false, &error));
    assert(store.record_evaluation_prediction(eval_ham_hit, Verdict::Ham, 0, 0.02, 2, 5, &error, Verdict::Ham, 0));
    assert(store.complete_evaluation(eval_ham_hit, false, &error));
    assert(store.record_evaluation_prediction(eval_pending, Verdict::Review, 35, 0.65, 2, 5, &error, Verdict::Review, 35));
    EvaluationStats evaluation_stats;
    assert(store.get_evaluation_stats(evaluation_stats, &error));
    assert(evaluation_stats.pending == 1);
    assert(evaluation_stats.labeled == 5);
    assert(evaluation_stats.spam_as_ham == 1);
    assert(evaluation_stats.spam_as_review == 1);
    assert(evaluation_stats.spam_as_spam == 1);
    assert(evaluation_stats.ham_as_ham == 1);
    assert(evaluation_stats.ham_as_review == 0);
    assert(evaluation_stats.ham_as_spam == 1);
    assert(evaluation_stats.symbol_labeled == 5);
    assert(evaluation_stats.symbol_spam_as_ham == 1);
    assert(evaluation_stats.symbol_spam_as_review == 1);
    assert(evaluation_stats.symbol_spam_as_spam == 1);
    assert(evaluation_stats.symbol_ham_as_ham == 1);
    assert(evaluation_stats.symbol_ham_as_review == 1);
    assert(evaluation_stats.symbol_ham_as_spam == 0);

    std::string integrity;
    assert(store.integrity_check(integrity, &error));
    assert(integrity == "ok");
    assert(store.backup_to(backup_path, &error));
    store.close();

    SqliteStore reopened(db_path);
    assert(reopened.open(&error));
    assert(reopened.train_once(spam_hash, "free prize winner offer", true, &error) == TrainStatus::Duplicate);
    assert(reopened.load_model(restored, &error));
    assert(restored.spam_samples() == 1);
    assert(restored.ham_samples() == 2);
    EvaluationStats reopened_evaluation;
    assert(reopened.get_evaluation_stats(reopened_evaluation, &error));
    assert(reopened_evaluation.pending == 1);
    assert(reopened_evaluation.labeled == 5);
    assert(reopened_evaluation.symbol_labeled == 5);
    assert(reopened.compact(3, 1, 365, &error));
    assert(reopened.integrity_check(integrity, &error));
    reopened.close();

    std::filesystem::remove(db_path);
    std::filesystem::remove(db_path + "-wal");
    std::filesystem::remove(db_path + "-shm");
    std::filesystem::remove(backup_path);
    std::filesystem::remove(db_path + ".precompact.bak");

    // Existing schema-v2 databases must be upgraded in place to schema v4.
    const auto migration_path = (temp / "becky_antispam_schema_v2.sqlite3").string();
    std::filesystem::remove(migration_path);
    std::filesystem::remove(migration_path + "-wal");
    std::filesystem::remove(migration_path + "-shm");
    sqlite3* legacy_db = nullptr;
    assert(sqlite3_open(migration_path.c_str(), &legacy_db) == SQLITE_OK);
    assert(sqlite3_exec(legacy_db,
        "CREATE TABLE evaluation_labels ("
        "message_hash TEXT PRIMARY KEY,label INTEGER NOT NULL,labeled_utc INTEGER NOT NULL);"
        "PRAGMA user_version=2;", nullptr, nullptr, nullptr) == SQLITE_OK);
    assert(sqlite3_close(legacy_db) == SQLITE_OK);
    {
        SqliteStore migrated(migration_path);
        assert(migrated.open(&error));
        EvaluationStats migrated_evaluation;
        assert(migrated.get_evaluation_stats(migrated_evaluation, &error));
        assert(migrated_evaluation.pending == 0);
        assert(migrated_evaluation.labeled == 0);
        assert(migrated.integrity_check(integrity, &error));
        assert(integrity == "ok");
    }
    {
        sqlite3* migrated_db = nullptr;
        assert(sqlite3_open(migration_path.c_str(), &migrated_db) == SQLITE_OK);
        sqlite3_stmt* version = nullptr;
        assert(sqlite3_prepare_v2(migrated_db, "PRAGMA user_version", -1, &version, nullptr) == SQLITE_OK);
        assert(sqlite3_step(version) == SQLITE_ROW);
        assert(sqlite3_column_int(version, 0) == 4);
        sqlite3_finalize(version);
        sqlite3_close(migrated_db);
    }
    // Reopening a v4 database must succeed; this catches a stale maximum-version guard.
    {
        SqliteStore reopened_v4(migration_path);
        assert(reopened_v4.open(&error));
        EvaluationStats reopened_v4_stats;
        assert(reopened_v4.get_evaluation_stats(reopened_v4_stats, &error));
        assert(reopened_v4_stats.pending == 0);
        assert(reopened_v4_stats.labeled == 0);
        assert(reopened_v4.integrity_check(integrity, &error));
        assert(integrity == "ok");
    }
    std::filesystem::remove(migration_path);
    std::filesystem::remove(migration_path + "-wal");
    std::filesystem::remove(migration_path + "-shm");

    const auto capped_path = (temp / "becky_antispam_vocab_cap.sqlite3").string();
    std::filesystem::remove(capped_path);
    std::filesystem::remove(capped_path + "-wal");
    std::filesystem::remove(capped_path + "-shm");
    std::string many_words;
    for (int i = 0; i < 110; ++i) many_words += "token" + std::to_string(i) + " ";
    SqliteStore capped_store(capped_path, 3);
    assert(capped_store.open(&error));
    assert(capped_store.train_once(std::string(64, 'd'), many_words, true, &error) == TrainStatus::Trained);
    StoreStats capped_stats;
    assert(capped_store.get_stats(capped_stats, &error));
    assert(capped_stats.vocabulary_size <= 3);
    capped_store.close();
    std::filesystem::remove(capped_path);
    std::filesystem::remove(capped_path + "-wal");
    std::filesystem::remove(capped_path + "-shm");

    // End-to-end parse -> classify -> SHA-256 deduplication -> SQLite training.
    const auto pipeline_path = (temp / "becky_antispam_pipeline.sqlite3").string();
    std::filesystem::remove(pipeline_path);
    std::filesystem::remove(pipeline_path + "-wal");
    std::filesystem::remove(pipeline_path + "-shm");
    {
        SqliteStore pipeline_store(pipeline_path);
        Settings evaluation_settings;
        evaluation_settings.enable_bayes_comparison = true;
        evaluation_settings.enable_symbol_comparison = true;
        MailPipeline pipeline(pipeline_store, evaluation_settings);
        assert(pipeline.initialize(&error));
        for (int i = 0; i < 6; ++i) {
            const auto spam_mail =
                "Message-ID: <spam" + std::to_string(i) + "@example.test>\r\n"
                "From: sender@example.test\r\n"
                "Subject: =?UTF-8?B?5pel5pys44Gu5Y+W6Kqt?=\r\n"
                "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
                "無料キャンペーン 当選 賞金を受け取る";
            const auto ham_mail =
                "Message-ID: <ham" + std::to_string(i) + "@example.test>\r\n"
                "From: colleague@example.test\r\n"
                "Subject: 会議資料\r\n"
                "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
                "会議資料 議事録と予定を共有します";
            assert(pipeline.train(spam_mail, true, nullptr, &error) == TrainStatus::Trained);
            assert(pipeline.train(ham_mail, false, nullptr, &error) == TrainStatus::Trained);
        }
        const std::string new_spam =
            "Message-ID: <newspam@example.test>\r\n"
            "Subject: 無料キャンペーン\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
            "当選 賞金を受け取る";
        const std::string new_ham =
            "Message-ID: <newham@example.test>\r\n"
            "Subject: 会議資料\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
            "議事録と予定を共有します";
        ParsedMail spam_parsed, ham_parsed;
        Result spam_result, ham_result;
        assert(pipeline.analyze(new_spam, spam_parsed, spam_result, &error));
        assert(pipeline.analyze(new_ham, ham_parsed, ham_result, &error));
        assert(spam_result.bayes_probability > ham_result.bayes_probability);
        assert(pipeline.record_prediction(new_spam, spam_result, &error));
        assert(pipeline.record_prediction(new_ham, ham_result, &error));

        // Evaluation-only labeling must update the confusion-matrix data without
        // changing the Bayes training corpus.
        const std::string evaluation_only_mail =
            "Message-ID: <evaluation-only@example.test>\r\n"
            "Subject: 会議の確認\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
            "明日の会議について確認します";
        ParsedMail evaluation_only_parsed;
        Result evaluation_only_result;
        assert(pipeline.analyze(evaluation_only_mail, evaluation_only_parsed,
                                evaluation_only_result, &error));
        assert(pipeline.record_prediction(evaluation_only_mail, evaluation_only_result,
                                          &error, true, 101));
        const auto ham_before_evaluation = pipeline.model().ham_samples();
        const auto spam_before_evaluation = pipeline.model().spam_samples();
        bool evaluation_matched = false;
        EvaluationRecord evaluation_record;
        assert(pipeline.label_evaluation(evaluation_only_mail, false,
                                         &evaluation_matched, &error, &evaluation_record));
        assert(evaluation_matched);
        assert(evaluation_record.case_number == 101);
        assert(evaluation_record.predicted_verdict == evaluation_only_result.verdict);
        assert(evaluation_record.comparison_available);
        assert(evaluation_record.comparison_verdict == evaluation_only_result.symbol_comparison.verdict);
        assert(evaluation_record.comparison_v2_available);
        assert(evaluation_record.comparison_v2_verdict == evaluation_only_result.symbol_experiment.verdict);
        // Re-running the same test message refreshes its anonymous case mapping
        // while preserving the already-confirmed actual label.
        assert(pipeline.record_prediction(evaluation_only_mail, evaluation_only_result,
                                          &error, true, 103));
        assert(pipeline.label_evaluation(evaluation_only_mail, false,
                                         &evaluation_matched, &error, &evaluation_record));
        assert(evaluation_matched);
        assert(evaluation_record.case_number == 103);
        EvaluationStats relabeled_stats;
        assert(pipeline.get_evaluation_stats(relabeled_stats, &error));
        assert(relabeled_stats.labeled == 1);
        assert(relabeled_stats.ham_as_ham + relabeled_stats.ham_as_review +
               relabeled_stats.ham_as_spam == 1);
        assert(pipeline.model().ham_samples() == ham_before_evaluation);
        assert(pipeline.model().spam_samples() == spam_before_evaluation);

        // Production capture may omit the comparison profile when test mode is off.
        const std::string no_comparison_mail =
            "Message-ID: <no-comparison@example.test>\r\n"
            "Subject: 業務連絡\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
            "定例会議の資料を共有します";
        ParsedMail no_comparison_parsed;
        Result no_comparison_result;
        assert(pipeline.analyze(no_comparison_mail, no_comparison_parsed,
                                no_comparison_result, &error));
        assert(pipeline.record_prediction(no_comparison_mail, no_comparison_result,
                                          &error, false, 102));
        assert(pipeline.label_evaluation(no_comparison_mail, false,
                                         &evaluation_matched, &error, &evaluation_record));
        assert(evaluation_matched);
        assert(evaluation_record.case_number == 102);
        assert(!evaluation_record.comparison_available);
        assert(!evaluation_record.comparison_v2_available);
        assert(pipeline.model().ham_samples() == ham_before_evaluation);
        assert(pipeline.model().spam_samples() == spam_before_evaluation);

        // Simulate the header inserted by BKC_OnBeforeFilter2 before Becky! saves the mail.
        const auto saved_spam = "X-AntiSpam-Classification: Spam\r\n" + new_spam + "\r\n";
        const auto saved_ham = "X-AntiSpam-Classification: Ham\r\n" + new_ham + "\r\n";
        assert(pipeline.train(saved_spam, true, nullptr, &error) == TrainStatus::Trained);
        assert(pipeline.train(saved_ham, false, nullptr, &error) == TrainStatus::Trained);
        EvaluationStats pipeline_evaluation;
        assert(pipeline.get_evaluation_stats(pipeline_evaluation, &error));
        assert(pipeline_evaluation.pending == 0);
        assert(pipeline_evaluation.labeled == 4);
        assert(pipeline_evaluation.symbol_labeled == 3);
        assert(pipeline_evaluation.spam_as_spam + pipeline_evaluation.spam_as_review +
               pipeline_evaluation.spam_as_ham == 1);
        assert(pipeline_evaluation.ham_as_ham + pipeline_evaluation.ham_as_review +
               pipeline_evaluation.ham_as_spam == 3);
        assert(pipeline.train(saved_spam, true, nullptr, &error) == TrainStatus::Duplicate);
    }
    std::filesystem::remove(pipeline_path);
    std::filesystem::remove(pipeline_path + "-wal");
    std::filesystem::remove(pipeline_path + "-shm");

    std::cout << "All Becky AntiSpam engine and storage tests passed.\n";
    return 0;
}
