#include "sqlite_store.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cmath>
#include <filesystem>
#include <exception>
#include <limits>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace beckyas {
namespace {

class Statement {
public:
    Statement(sqlite3* db, const char* sql) : db_(db) {
        rc_ = sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr);
    }
    ~Statement() { if (stmt_) sqlite3_finalize(stmt_); }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    bool ok() const { return rc_ == SQLITE_OK && stmt_ != nullptr; }
    sqlite3_stmt* get() const { return stmt_; }
private:
    sqlite3* db_;
    sqlite3_stmt* stmt_ = nullptr;
    int rc_ = SQLITE_ERROR;
};

bool exec(sqlite3* db, const char* sql, std::string* error) {
    char* message = nullptr;
    const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &message);
    if (rc == SQLITE_OK) return true;
    if (error) *error = message ? message : sqlite3_errmsg(db);
    sqlite3_free(message);
    return false;
}

void set_error(sqlite3* db, std::string* error, const char* fallback) {
    if (error) *error = db ? sqlite3_errmsg(db) : fallback;
}

bool valid_hash(const std::string& hash) {
    if (hash.size() != 64) return false;
    return std::all_of(hash.begin(), hash.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

std::string normalize_hash(std::string hash) {
    std::transform(hash.begin(), hash.end(), hash.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return hash;
}

std::int64_t now_utc() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

bool begin(sqlite3* db, std::string* error) {
    return exec(db, "BEGIN IMMEDIATE", error);
}
void rollback(sqlite3* db) { sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr); }

} // namespace

SqliteStore::SqliteStore(std::string database_path, std::size_t max_vocabulary)
    : database_path_(std::move(database_path)),
      max_vocabulary_(std::max<std::size_t>(1, max_vocabulary)) {}

SqliteStore::~SqliteStore() { close(); }

bool SqliteStore::is_open() const noexcept { return db_ != nullptr; }

void SqliteStore::close() noexcept {
    if (db_) {
        sqlite3_close_v2(db_);
        db_ = nullptr;
    }
}

bool SqliteStore::open(std::string* error) {
    if (db_) return true;
    if (database_path_.empty()) {
        if (error) *error = "データベースパスが空です";
        return false;
    }

    try {
        const auto parent = std::filesystem::u8path(database_path_).parent_path();
        if (!parent.empty()) std::filesystem::create_directories(parent);
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }

    const int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    const int rc = sqlite3_open_v2(database_path_.c_str(), &db_, flags, nullptr);
    if (rc != SQLITE_OK) {
        set_error(db_, error, "SQLiteを開けません");
        close();
        return false;
    }

    sqlite3_busy_timeout(db_, 5000);
    if (!exec(db_, "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;", error) ||
        !exec(db_,
            "CREATE TABLE IF NOT EXISTS meta ("
            " key TEXT PRIMARY KEY, value INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS token_stats ("
            " token TEXT PRIMARY KEY,"
            " spam_docs INTEGER NOT NULL DEFAULT 0 CHECK(spam_docs>=0),"
            " ham_docs INTEGER NOT NULL DEFAULT 0 CHECK(ham_docs>=0),"
            " last_seen_utc INTEGER NOT NULL DEFAULT 0);"
            "CREATE INDEX IF NOT EXISTS idx_token_stats_last_seen ON token_stats(last_seen_utc);"
            "CREATE TABLE IF NOT EXISTS training_receipts ("
            " message_hash TEXT PRIMARY KEY CHECK(length(message_hash)=64),"
            " label INTEGER NOT NULL CHECK(label IN (0,1)),"
            " trained_utc INTEGER NOT NULL);"
            "CREATE INDEX IF NOT EXISTS idx_training_receipts_trained ON training_receipts(trained_utc);",
            error)) {
        close();
        return false;
    }

    int schema_version = 0;
    {
        Statement version(db_, "PRAGMA user_version");
        if (!version.ok() || sqlite3_step(version.get()) != SQLITE_ROW) {
            set_error(db_, error, "スキーマバージョンを確認できません");
            close();
            return false;
        }
        schema_version = sqlite3_column_int(version.get(), 0);
    }
    if (schema_version > 3) {
        if (error) *error = "未対応のデータベーススキーマです";
        close();
        return false;
    }
    if (schema_version == 0 && !exec(db_, "PRAGMA user_version=1", error)) {
        close();
        return false;
    }
    if (schema_version < 2) {
        if (!exec(db_,
            "CREATE TABLE IF NOT EXISTS evaluation_labels ("
            " message_hash TEXT PRIMARY KEY CHECK(length(message_hash)=64),"
            " label INTEGER NOT NULL CHECK(label IN (0,1)),"
            " labeled_utc INTEGER NOT NULL);"
            "CREATE INDEX IF NOT EXISTS idx_evaluation_labels_labeled ON evaluation_labels(labeled_utc);"
            "PRAGMA user_version=2;", error)) {
            close();
            return false;
        }
    }
    if (schema_version < 3) {
        if (!exec(db_,
            "CREATE TABLE IF NOT EXISTS evaluation_results ("
            " message_hash TEXT PRIMARY KEY CHECK(length(message_hash)=64),"
            " actual_label INTEGER CHECK(actual_label IS NULL OR actual_label IN (0,1)),"
            " predicted_verdict INTEGER NOT NULL CHECK(predicted_verdict IN (0,1,2)),"
            " score INTEGER NOT NULL,"
            " bayes_probability REAL NOT NULL CHECK(bayes_probability>=0.0 AND bayes_probability<=1.0),"
            " ham_samples INTEGER NOT NULL DEFAULT 0 CHECK(ham_samples>=0),"
            " spam_samples INTEGER NOT NULL DEFAULT 0 CHECK(spam_samples>=0),"
            " predicted_utc INTEGER NOT NULL,"
            " labeled_utc INTEGER);"
            "CREATE INDEX IF NOT EXISTS idx_evaluation_results_status_time "
            "ON evaluation_results(actual_label,predicted_utc);"
            "PRAGMA user_version=3;", error)) {
            close();
            return false;
        }
    }
    return true;
}

TrainStatus SqliteStore::train_once(const std::string& message_hash,
                                    const std::string& text,
                                    bool spam,
                                    std::string* error) {
    if (!db_) {
        if (error) *error = "データベースが開かれていません";
        return TrainStatus::Error;
    }
    if (!valid_hash(message_hash)) {
        if (error) *error = "message_hashにはSHA-256の64桁16進数を指定してください";
        return TrainStatus::Error;
    }
    if (text.size() > 1024 * 1024) {
        if (error) *error = "学習対象テキストが1MiBを超えています";
        return TrainStatus::Error;
    }
    if (!begin(db_, error)) return TrainStatus::Error;

    const auto hash = normalize_hash(message_hash);
    bool reclassify = false;
    bool old_spam = false;
    {
        Statement receipt(db_,
            "INSERT INTO training_receipts(message_hash,label,trained_utc) VALUES(?1,?2,?3)");
        if (!receipt.ok()) {
            set_error(db_, error, "学習履歴SQLを準備できません");
            rollback(db_);
            return TrainStatus::Error;
        }
        sqlite3_bind_text(receipt.get(), 1, hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(receipt.get(), 2, spam ? 1 : 0);
        sqlite3_bind_int64(receipt.get(), 3, now_utc());
        const int receipt_rc = sqlite3_step(receipt.get());
        if ((receipt_rc & 0xff) == SQLITE_CONSTRAINT) {
            Statement existing(db_, "SELECT label FROM training_receipts WHERE message_hash=?1");
            if (!existing.ok()) {
                set_error(db_, error, "既存学習履歴SQLを準備できません");
                rollback(db_);
                return TrainStatus::Error;
            }
            sqlite3_bind_text(existing.get(), 1, hash.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(existing.get()) != SQLITE_ROW) {
                set_error(db_, error, "既存学習履歴を確認できません");
                rollback(db_);
                return TrainStatus::Error;
            }
            old_spam = sqlite3_column_int(existing.get(), 0) == 1;
            if (old_spam == spam) {
                rollback(db_);
                return TrainStatus::Duplicate;
            }
            reclassify = true;
        } else if (receipt_rc != SQLITE_DONE) {
            set_error(db_, error, "学習履歴を登録できません");
            rollback(db_);
            return TrainStatus::Error;
        }
    }

    if (reclassify) {
        Statement update(db_,
            "UPDATE training_receipts SET label=?1,trained_utc=?2 WHERE message_hash=?3");
        if (!update.ok()) {
            set_error(db_, error, "学習ラベル更新SQLを準備できません");
            rollback(db_);
            return TrainStatus::Error;
        }
        sqlite3_bind_int(update.get(), 1, spam ? 1 : 0);
        sqlite3_bind_int64(update.get(), 2, now_utc());
        sqlite3_bind_text(update.get(), 3, hash.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(update.get()) != SQLITE_DONE) {
            set_error(db_, error, "学習ラベルを更新できません");
            rollback(db_);
            return TrainStatus::Error;
        }
    }

    const auto tokens = tokenize(text);
    std::unordered_set<std::string> unique(tokens.begin(), tokens.end());
    Statement upsert(db_,
        "INSERT INTO token_stats(token,spam_docs,ham_docs,last_seen_utc) "
        "VALUES(?1,?2,?3,?4) "
        "ON CONFLICT(token) DO UPDATE SET "
        "spam_docs=MAX(0,spam_docs+?5),"
        "ham_docs=MAX(0,ham_docs+?6),"
        "last_seen_utc=excluded.last_seen_utc");
    if (!upsert.ok()) {
        set_error(db_, error, "単語統計SQLを準備できません");
        rollback(db_);
        return TrainStatus::Error;
    }
    const int old_spam_delta = reclassify && old_spam ? 1 : 0;
    const int old_ham_delta = reclassify && !old_spam ? 1 : 0;
    const int spam_delta = (spam ? 1 : 0) - old_spam_delta;
    const int ham_delta = (spam ? 0 : 1) - old_ham_delta;
    const auto timestamp = now_utc();
    for (const auto& token : unique) {
        sqlite3_reset(upsert.get());
        sqlite3_clear_bindings(upsert.get());
        sqlite3_bind_text(upsert.get(), 1, token.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(upsert.get(), 2, spam ? 1 : 0);
        sqlite3_bind_int(upsert.get(), 3, spam ? 0 : 1);
        sqlite3_bind_int64(upsert.get(), 4, timestamp);
        sqlite3_bind_int(upsert.get(), 5, spam_delta);
        sqlite3_bind_int(upsert.get(), 6, ham_delta);
        if (sqlite3_step(upsert.get()) != SQLITE_DONE) {
            set_error(db_, error, "単語統計を更新できません");
            rollback(db_);
            return TrainStatus::Error;
        }
    }

    Statement samples(db_,
        "INSERT INTO meta(key,value) VALUES(?1,?2) "
        "ON CONFLICT(key) DO UPDATE SET value=MAX(0,value+excluded.value)");
    if (!samples.ok()) {
        set_error(db_, error, "学習件数SQLを準備できません");
        rollback(db_);
        return TrainStatus::Error;
    }
    const int sample_deltas[2] = {spam_delta, ham_delta};
    const char* sample_keys[2] = {"spam_samples", "ham_samples"};
    for (int i = 0; i < 2; ++i) {
        if (sample_deltas[i] == 0) continue;
        sqlite3_reset(samples.get());
        sqlite3_clear_bindings(samples.get());
        sqlite3_bind_text(samples.get(), 1, sample_keys[i], -1, SQLITE_STATIC);
        sqlite3_bind_int(samples.get(), 2, sample_deltas[i]);
        if (sqlite3_step(samples.get()) != SQLITE_DONE) {
            set_error(db_, error, "学習件数を更新できません");
            rollback(db_);
            return TrainStatus::Error;
        }
    }

    std::size_t current_vocabulary = 0;
    {
        Statement count(db_, "SELECT count(*) FROM token_stats");
        if (!count.ok() || sqlite3_step(count.get()) != SQLITE_ROW) {
            set_error(db_, error, "語彙数を確認できません");
            rollback(db_);
            return TrainStatus::Error;
        }
        current_vocabulary = static_cast<std::size_t>(sqlite3_column_int64(count.get(), 0));
    }
    const auto extra = std::max<std::size_t>(100, max_vocabulary_ / 20);
    const auto trigger = max_vocabulary_ > std::numeric_limits<std::size_t>::max() - extra
        ? std::numeric_limits<std::size_t>::max() : max_vocabulary_ + extra;
    if (current_vocabulary > trigger) {
        Statement prune(db_,
            "DELETE FROM token_stats WHERE token NOT IN ("
            " SELECT token FROM token_stats ORDER BY (spam_docs+ham_docs) DESC, token ASC LIMIT ?1)");
        if (!prune.ok()) {
            set_error(db_, error, "語彙上限SQLを準備できません");
            rollback(db_);
            return TrainStatus::Error;
        }
        sqlite3_bind_int64(prune.get(), 1, static_cast<sqlite3_int64>(
            std::min<std::size_t>(max_vocabulary_,
                static_cast<std::size_t>(std::numeric_limits<sqlite3_int64>::max()))));
        if (sqlite3_step(prune.get()) != SQLITE_DONE) {
            set_error(db_, error, "語彙上限を適用できません");
            rollback(db_);
            return TrainStatus::Error;
        }
    }

    if (!exec(db_, "COMMIT", error)) {
        rollback(db_);
        return TrainStatus::Error;
    }
    return reclassify ? TrainStatus::Reclassified : TrainStatus::Trained;
}

bool SqliteStore::set_evaluation_label(const std::string& message_hash,
                                         bool spam,
                                         std::string* error) {
    if (!db_) {
        if (error) *error = "データベースが開かれていません";
        return false;
    }
    if (!valid_hash(message_hash)) {
        if (error) *error = "message_hashにはSHA-256の64桁16進数を指定してください";
        return false;
    }
    Statement label(db_,
        "INSERT INTO evaluation_labels(message_hash,label,labeled_utc) VALUES(?1,?2,?3) "
        "ON CONFLICT(message_hash) DO UPDATE SET label=excluded.label,labeled_utc=excluded.labeled_utc");
    if (!label.ok()) {
        set_error(db_, error, "評価ラベルSQLを準備できません");
        return false;
    }
    const auto hash = normalize_hash(message_hash);
    sqlite3_bind_text(label.get(), 1, hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(label.get(), 2, spam ? 1 : 0);
    sqlite3_bind_int64(label.get(), 3, now_utc());
    if (sqlite3_step(label.get()) != SQLITE_DONE) {
        set_error(db_, error, "評価ラベルを保存できません");
        return false;
    }
    return true;
}

bool SqliteStore::record_evaluation_prediction(const std::string& message_hash,
                                               Verdict predicted,
                                               int score,
                                               double bayes_probability,
                                               std::size_t ham_samples,
                                               std::size_t spam_samples,
                                               std::string* error) {
    if (!db_) {
        if (error) *error = "データベースが開かれていません";
        return false;
    }
    if (!valid_hash(message_hash)) {
        if (error) *error = "message_hashにはSHA-256の64桁16進数を指定してください";
        return false;
    }
    if (!std::isfinite(bayes_probability) ||
        bayes_probability < 0.0 || bayes_probability > 1.0) {
        if (error) *error = "Bayes確率は0.0から1.0の範囲で指定してください";
        return false;
    }

    const int verdict = static_cast<int>(predicted);
    if (verdict < 0 || verdict > 2) {
        if (error) *error = "未対応の判定結果です";
        return false;
    }

    const auto hash = normalize_hash(message_hash);
    Statement prediction(db_,
        "INSERT OR IGNORE INTO evaluation_results("
        "message_hash,actual_label,predicted_verdict,score,bayes_probability,"
        "ham_samples,spam_samples,predicted_utc,labeled_utc) "
        "VALUES(?1,NULL,?2,?3,?4,?5,?6,?7,NULL)");
    if (!prediction.ok()) {
        set_error(db_, error, "評価予測SQLを準備できません");
        return false;
    }
    sqlite3_bind_text(prediction.get(), 1, hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(prediction.get(), 2, verdict);
    sqlite3_bind_int(prediction.get(), 3, score);
    sqlite3_bind_double(prediction.get(), 4, bayes_probability);
    sqlite3_bind_int64(prediction.get(), 5, static_cast<sqlite3_int64>(ham_samples));
    sqlite3_bind_int64(prediction.get(), 6, static_cast<sqlite3_int64>(spam_samples));
    sqlite3_bind_int64(prediction.get(), 7, now_utc());
    if (sqlite3_step(prediction.get()) != SQLITE_DONE) {
        set_error(db_, error, "評価予測を保存できません");
        return false;
    }

    // Unlabeled predictions are temporary. Keep the pending queue bounded.
    Statement expire(db_,
        "DELETE FROM evaluation_results "
        "WHERE actual_label IS NULL AND predicted_utc < ?1");
    if (!expire.ok()) {
        set_error(db_, error, "期限切れ評価予測SQLを準備できません");
        return false;
    }
    sqlite3_bind_int64(expire.get(), 1, now_utc() - 30LL * 24LL * 60LL * 60LL);
    if (sqlite3_step(expire.get()) != SQLITE_DONE) {
        set_error(db_, error, "期限切れ評価予測を整理できません");
        return false;
    }
    return true;
}

bool SqliteStore::complete_evaluation(const std::string& message_hash,
                                      bool spam,
                                      std::string* error) {
    if (!db_) {
        if (error) *error = "データベースが開かれていません";
        return false;
    }
    if (!valid_hash(message_hash)) {
        if (error) *error = "message_hashにはSHA-256の64桁16進数を指定してください";
        return false;
    }
    const auto hash = normalize_hash(message_hash);
    Statement label(db_,
        "UPDATE evaluation_results SET actual_label=?1,labeled_utc=?2 "
        "WHERE message_hash=?3");
    if (!label.ok()) {
        set_error(db_, error, "評価ラベル確定SQLを準備できません");
        return false;
    }
    sqlite3_bind_int(label.get(), 1, spam ? 1 : 0);
    sqlite3_bind_int64(label.get(), 2, now_utc());
    sqlite3_bind_text(label.get(), 3, hash.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(label.get()) != SQLITE_DONE) {
        set_error(db_, error, "評価ラベルを確定できません");
        return false;
    }
    // No matching prediction is not an error (e.g. mail received before this feature).
    return true;
}

bool SqliteStore::get_evaluation_stats(EvaluationStats& stats,
                                       std::string* error) const {
    if (!db_) {
        if (error) *error = "データベースが開かれていません";
        return false;
    }
    stats = {};
    Statement summary(db_,
        "SELECT "
        "(SELECT count(*) FROM evaluation_results WHERE actual_label IS NULL),"
        "(SELECT count(*) FROM evaluation_results WHERE actual_label IS NOT NULL),"
        "COALESCE(SUM(CASE WHEN actual_label=1 AND predicted_verdict=0 THEN 1 ELSE 0 END),0),"
        "COALESCE(SUM(CASE WHEN actual_label=1 AND predicted_verdict=1 THEN 1 ELSE 0 END),0),"
        "COALESCE(SUM(CASE WHEN actual_label=1 AND predicted_verdict=2 THEN 1 ELSE 0 END),0),"
        "COALESCE(SUM(CASE WHEN actual_label=0 AND predicted_verdict=0 THEN 1 ELSE 0 END),0),"
        "COALESCE(SUM(CASE WHEN actual_label=0 AND predicted_verdict=1 THEN 1 ELSE 0 END),0),"
        "COALESCE(SUM(CASE WHEN actual_label=0 AND predicted_verdict=2 THEN 1 ELSE 0 END),0) "
        "FROM evaluation_results WHERE actual_label IS NOT NULL");
    if (!summary.ok() || sqlite3_step(summary.get()) != SQLITE_ROW) {
        set_error(db_, error, "評価統計を取得できません");
        return false;
    }
    stats.pending = static_cast<std::size_t>(sqlite3_column_int64(summary.get(), 0));
    stats.labeled = static_cast<std::size_t>(sqlite3_column_int64(summary.get(), 1));
    stats.spam_as_ham = static_cast<std::size_t>(sqlite3_column_int64(summary.get(), 2));
    stats.spam_as_review = static_cast<std::size_t>(sqlite3_column_int64(summary.get(), 3));
    stats.spam_as_spam = static_cast<std::size_t>(sqlite3_column_int64(summary.get(), 4));
    stats.ham_as_ham = static_cast<std::size_t>(sqlite3_column_int64(summary.get(), 5));
    stats.ham_as_review = static_cast<std::size_t>(sqlite3_column_int64(summary.get(), 6));
    stats.ham_as_spam = static_cast<std::size_t>(sqlite3_column_int64(summary.get(), 7));
    return true;
}

bool SqliteStore::load_model(BayesianModel& model, std::string* error) const {
    if (!db_) {
        if (error) *error = "データベースが開かれていません";
        return false;
    }
    std::size_t spam = 0, ham = 0;
    Statement meta(db_, "SELECT key,value FROM meta WHERE key IN ('spam_samples','ham_samples')");
    if (!meta.ok()) {
        set_error(db_, error, "学習件数SQLを準備できません");
        return false;
    }
    int rc;
    while ((rc = sqlite3_step(meta.get())) == SQLITE_ROW) {
        const auto* key = reinterpret_cast<const char*>(sqlite3_column_text(meta.get(), 0));
        const auto value = static_cast<std::size_t>(std::max<sqlite3_int64>(0, sqlite3_column_int64(meta.get(), 1)));
        if (key && std::string(key) == "spam_samples") spam = value;
        else if (key && std::string(key) == "ham_samples") ham = value;
    }
    if (rc != SQLITE_DONE) {
        set_error(db_, error, "学習件数を読み込めません");
        return false;
    }

    std::vector<BayesianModel::TokenCount> counts;
    Statement words(db_, "SELECT token,spam_docs,ham_docs FROM token_stats "
                          "ORDER BY (spam_docs+ham_docs) DESC, token ASC LIMIT ?1");
    if (!words.ok()) {
        set_error(db_, error, "単語統計SQLを準備できません");
        return false;
    }
    sqlite3_bind_int64(words.get(), 1, static_cast<sqlite3_int64>(model.max_vocabulary()));
    while ((rc = sqlite3_step(words.get())) == SQLITE_ROW) {
        const auto* token = reinterpret_cast<const char*>(sqlite3_column_text(words.get(), 0));
        if (!token) continue;
        counts.push_back({token,
            static_cast<std::size_t>(std::max<sqlite3_int64>(0, sqlite3_column_int64(words.get(), 1))),
            static_cast<std::size_t>(std::max<sqlite3_int64>(0, sqlite3_column_int64(words.get(), 2)))});
    }
    if (rc != SQLITE_DONE) {
        set_error(db_, error, "単語統計を読み込めません");
        return false;
    }
    model.restore(spam, ham, counts);
    return true;
}

bool SqliteStore::get_stats(StoreStats& stats, std::string* error) const {
    if (!db_) {
        if (error) *error = "データベースが開かれていません";
        return false;
    }
    stats = {};
    Statement meta(db_, "SELECT key,value FROM meta WHERE key IN ('spam_samples','ham_samples')");
    if (!meta.ok()) { set_error(db_, error, "統計SQLを準備できません"); return false; }
    int rc;
    while ((rc = sqlite3_step(meta.get())) == SQLITE_ROW) {
        const auto* key = reinterpret_cast<const char*>(sqlite3_column_text(meta.get(), 0));
        const auto value = static_cast<std::size_t>(std::max<sqlite3_int64>(0, sqlite3_column_int64(meta.get(), 1)));
        if (key && std::string(key) == "spam_samples") stats.spam_samples = value;
        else if (key && std::string(key) == "ham_samples") stats.ham_samples = value;
    }
    if (rc != SQLITE_DONE) { set_error(db_, error, "学習件数を取得できません"); return false; }

    Statement counts(db_, "SELECT (SELECT count(*) FROM token_stats),"
                          "(SELECT count(*) FROM training_receipts)");
    if (!counts.ok() || sqlite3_step(counts.get()) != SQLITE_ROW) {
        set_error(db_, error, "DB統計を取得できません");
        return false;
    }
    stats.vocabulary_size = static_cast<std::size_t>(sqlite3_column_int64(counts.get(), 0));
    stats.training_receipts = static_cast<std::size_t>(sqlite3_column_int64(counts.get(), 1));
    // Include WAL/SHM sidecars: page_count alone omits live WAL growth.
    std::error_code size_error;
    const auto db_file = std::filesystem::u8path(database_path_);
    const auto add_file_size = [&stats, &size_error](const std::filesystem::path& path) {
        size_error.clear();
        if (std::filesystem::exists(path, size_error) && !size_error) {
            const auto bytes = std::filesystem::file_size(path, size_error);
            if (!size_error) stats.database_bytes += static_cast<std::uint64_t>(bytes);
        }
    };
    add_file_size(db_file);
    add_file_size(std::filesystem::u8path(database_path_ + "-wal"));
    add_file_size(std::filesystem::u8path(database_path_ + "-shm"));
    if (size_error) {
        if (error) *error = size_error.message();
        return false;
    }
    return true;
}

bool SqliteStore::compact(std::size_t max_vocabulary,
                          std::size_t min_total_frequency,
                          int receipt_retention_days,
                          std::string* error) {
    if (!db_) { if (error) *error = "データベースが開かれていません"; return false; }
    if (receipt_retention_days < 0) {
        if (error) *error = "履歴保持日数は0以上を指定してください";
        return false;
    }

    // Keep one immediately preceding snapshot; never prune without a recoverable copy.
    if (!backup_to(database_path_ + ".precompact.bak", error)) return false;

    {
        if (!begin(db_, error)) return false;

        Statement rare(db_, "DELETE FROM token_stats WHERE (spam_docs+ham_docs) < ?1");
        if (!rare.ok()) { set_error(db_, error, "低頻度語削除SQLを準備できません"); rollback(db_); return false; }
        const auto min_frequency = std::min<std::size_t>(min_total_frequency,
            static_cast<std::size_t>(std::numeric_limits<sqlite3_int64>::max()));
        sqlite3_bind_int64(rare.get(), 1, static_cast<sqlite3_int64>(min_frequency));
        if (sqlite3_step(rare.get()) != SQLITE_DONE) { set_error(db_, error, "低頻度語を削除できません"); rollback(db_); return false; }

        Statement excess(db_,
            "DELETE FROM token_stats WHERE token NOT IN ("
            " SELECT token FROM token_stats ORDER BY (spam_docs+ham_docs) DESC, token ASC LIMIT ?1)");
        if (!excess.ok()) { set_error(db_, error, "語彙上限SQLを準備できません"); rollback(db_); return false; }
        const auto capped = std::min<std::size_t>(max_vocabulary,
            static_cast<std::size_t>(std::numeric_limits<sqlite3_int64>::max()));
        sqlite3_bind_int64(excess.get(), 1, static_cast<sqlite3_int64>(std::max<std::size_t>(1, capped)));
        if (sqlite3_step(excess.get()) != SQLITE_DONE) { set_error(db_, error, "語彙を整理できません"); rollback(db_); return false; }

        if (receipt_retention_days > 0) {
            Statement receipts(db_, "DELETE FROM training_receipts WHERE trained_utc < ?1");
            if (!receipts.ok()) { set_error(db_, error, "履歴整理SQLを準備できません"); rollback(db_); return false; }
            const auto cutoff = now_utc() - static_cast<std::int64_t>(receipt_retention_days) * 86400;
            sqlite3_bind_int64(receipts.get(), 1, cutoff);
            if (sqlite3_step(receipts.get()) != SQLITE_DONE) { set_error(db_, error, "古い履歴を整理できません"); rollback(db_); return false; }
        }
        if (!exec(db_, "COMMIT", error)) { rollback(db_); return false; }
    }

    // Finalize all write statements before checkpointing and rebuilding the database.
    if (!exec(db_, "PRAGMA wal_checkpoint(TRUNCATE)", error)) return false;
    if (!exec(db_, "VACUUM", error)) return false;
    return true;
}

bool SqliteStore::integrity_check(std::string& result, std::string* error) const {
    if (!db_) { if (error) *error = "データベースが開かれていません"; return false; }
    Statement check(db_, "PRAGMA integrity_check");
    if (!check.ok() || sqlite3_step(check.get()) != SQLITE_ROW) {
        set_error(db_, error, "整合性チェックを実行できません");
        return false;
    }
    const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(check.get(), 0));
    result = value ? value : "";
    return result == "ok";
}

bool SqliteStore::backup_to(const std::string& destination_path, std::string* error) const {
    if (!db_) { if (error) *error = "データベースが開かれていません"; return false; }
    if (destination_path.empty() || destination_path == database_path_) {
        if (error) *error = "バックアップ先には別のファイルを指定してください";
        return false;
    }
    try {
        const auto parent = std::filesystem::u8path(destination_path).parent_path();
        if (!parent.empty()) std::filesystem::create_directories(parent);
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
    sqlite3* destination = nullptr;
    const int open_rc = sqlite3_open_v2(destination_path.c_str(), &destination,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (open_rc != SQLITE_OK) {
        if (error) *error = destination ? sqlite3_errmsg(destination) : "バックアップ先を開けません";
        if (destination) sqlite3_close_v2(destination);
        return false;
    }
    sqlite3_backup* backup = sqlite3_backup_init(destination, "main", db_, "main");
    if (!backup) {
        if (error) *error = sqlite3_errmsg(destination);
        sqlite3_close_v2(destination);
        return false;
    }
    int rc;
    do {
        rc = sqlite3_backup_step(backup, -1);
        if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED) sqlite3_sleep(25);
    } while (rc == SQLITE_BUSY || rc == SQLITE_LOCKED);
    const int finish_rc = sqlite3_backup_finish(backup);
    const bool ok = rc == SQLITE_DONE && finish_rc == SQLITE_OK;
    if (!ok && error) *error = sqlite3_errmsg(destination);
    sqlite3_close_v2(destination);
    return ok;
}



} // namespace beckyas
