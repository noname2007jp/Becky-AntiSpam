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
    assert(brand_filter.classify(amex_legitimate).verdict == Verdict::Ham);

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

    BayesianModel model;
    for (int i = 0; i < 6; ++i) {
        model.train("当選 無料 賞金 今すぐ応募", true);
        model.train("会議 議事録 業務 予定", false);
    }
    assert(model.spam_probability("無料 賞金 当選") >
           model.spam_probability("会議 議事録"));

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
    assert(reopened.compact(3, 1, 365, &error));
    assert(reopened.integrity_check(integrity, &error));
    reopened.close();

    std::filesystem::remove(db_path);
    std::filesystem::remove(db_path + "-wal");
    std::filesystem::remove(db_path + "-shm");
    std::filesystem::remove(backup_path);
    std::filesystem::remove(db_path + ".precompact.bak");

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
        MailPipeline pipeline(pipeline_store);
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
        ParsedMail pipeline_parsed;
        Result spam_result, ham_result;
        assert(pipeline.analyze(new_spam, pipeline_parsed, spam_result, &error));
        assert(pipeline.analyze(new_ham, pipeline_parsed, ham_result, &error));
        assert(spam_result.bayes_probability > ham_result.bayes_probability);
        assert(pipeline.train(new_spam, true, nullptr, &error) == TrainStatus::Trained);
        assert(pipeline.train(new_spam, true, nullptr, &error) == TrainStatus::Duplicate);
    }
    std::filesystem::remove(pipeline_path);
    std::filesystem::remove(pipeline_path + "-wal");
    std::filesystem::remove(pipeline_path + "-shm");

    std::cout << "All Becky AntiSpam engine and storage tests passed.\n";
    return 0;
}
