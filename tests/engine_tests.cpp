#include "antispam.hpp"
#include "sqlite_store.hpp"

#include <cassert>
#include <filesystem>
#include <iostream>

using namespace beckyas;

int main() {
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

    std::string error;
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
