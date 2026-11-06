#include "antispam.hpp"
#include "sqlite_store.hpp"
#include "message_parser.hpp"
#include "sha256.hpp"

#include <cassert>
#include <filesystem>
#include <iostream>

using namespace beckyas;

int main() {
    std::string error;

    // SHA-256 known-answer tests (FIPS 180-4).
    assert(sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert(sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // Header unfolding, RFC 2047 Q decoding, MIME multipart and transfer decoding.
    const std::string raw_mail =
        "From: Example Sender <sender@example.jp>\r\n"
        "Return-Path: <bounce@example.jp>\r\n"
        "Subject: =?UTF-8?Q?Hello=20World?=\r\n"
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
    assert(parsed.message.spf_result.empty());
    assert(parsed.message.dkim_result.empty());
    assert(parsed.message.dmarc_result.empty());
    assert(parsed.headers.size() >= 7);
    assert(parsed.headers[3].name == "x-long");
    assert(parsed.headers[3].value == "first second");
    assert(parsed.attachments.size() == 1);
    assert(parsed.attachments[0].filename == "sample.bin");
    assert(parsed.mime_parts == 3);
    assert(sha256_hex(raw_mail).size() == 64);

    ParseLimits tiny_limits;
    tiny_limits.max_message_bytes = 8;
    MessageParser tiny_parser(tiny_limits);
    ParsedMail rejected;
    assert(!tiny_parser.parse(raw_mail, rejected, &error));

    Filter filter;
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

    std::cout << "All Becky AntiSpam engine and storage tests passed.\n";
    return 0;
}
