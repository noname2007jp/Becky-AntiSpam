#include "sqlite_store.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <filesystem>
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

SqliteStore::SqliteStore(std::string database_path)
    : database_path_(std::move(database_path)) {}

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

    Statement version(db_, "PRAGMA user_version");
    if (!version.ok() || sqlite3_step(version.get()) != SQLITE_ROW) {
        set_error(db_, error, "スキーマバージョンを確認できません");
        close();
        return false;
    }
    const int schema_version = sqlite3_column_int(version.get(), 0);
    if (schema_version > 1) {
        if (error) *error = "未対応のデータベーススキーマです";
        close();
        return false;
    }
    if (schema_version == 0 && !exec(db_, "PRAGMA user_version=1", error)) {
        close();
        return false;
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
    if (!begin(db_, error)) return TrainStatus::Error;

    Statement receipt(db_,
        "INSERT INTO training_receipts(message_hash,label,trained_utc) VALUES(?1,?2,?3)");
    if (!receipt.ok()) {
        set_error(db_, error, "学習履歴SQLを準備できません");
        rollback(db_);
        return TrainStatus::Error;
    }
    const auto hash = normalize_hash(message_hash);
    sqlite3_bind_text(receipt.get(), 1, hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(receipt.get(), 2, spam ? 1 : 0);
    sqlite3_bind_int64(receipt.get(), 3, now_utc());
    const int receipt_rc = sqlite3_step(receipt.get());
    if (receipt_rc == SQLITE_CONSTRAINT_PRIMARYKEY || receipt_rc == SQLITE_CONSTRAINT_UNIQUE) {
        rollback(db_);
        return TrainStatus::Duplicate;
    }
    if (receipt_rc != SQLITE_DONE) {
        set_error(db_, error, "学習履歴を登録できません");
        rollback(db_);
        return TrainStatus::Error;
    }

    const auto tokens = tokenize(text);
    std::unordered_set<std::string> unique(tokens.begin(), tokens.end());
    Statement upsert(db_,
        "INSERT INTO token_stats(token,spam_docs,ham_docs,last_seen_utc) "
        "VALUES(?1,?2,?3,?4) "
        "ON CONFLICT(token) DO UPDATE SET "
        "spam_docs=spam_docs+excluded.spam_docs,"
        "ham_docs=ham_docs+excluded.ham_docs,"
        "last_seen_utc=excluded.last_seen_utc");
    if (!upsert.ok()) {
        set_error(db_, error, "単語統計SQLを準備できません");
        rollback(db_);
        return TrainStatus::Error;
    }
    const auto timestamp = now_utc();
    for (const auto& token : unique) {
        sqlite3_reset(upsert.get());
        sqlite3_clear_bindings(upsert.get());
        sqlite3_bind_text(upsert.get(), 1, token.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(upsert.get(), 2, spam ? 1 : 0);
        sqlite3_bind_int(upsert.get(), 3, spam ? 0 : 1);
        sqlite3_bind_int64(upsert.get(), 4, timestamp);
        if (sqlite3_step(upsert.get()) != SQLITE_DONE) {
            set_error(db_, error, "単語統計を更新できません");
            rollback(db_);
            return TrainStatus::Error;
        }
    }

    Statement samples(db_,
        "INSERT INTO meta(key,value) VALUES(?1,1) "
        "ON CONFLICT(key) DO UPDATE SET value=value+1");
    if (!samples.ok()) {
        set_error(db_, error, "学習件数SQLを準備できません");
        rollback(db_);
        return TrainStatus::Error;
    }
    const char* key = spam ? "spam_samples" : "ham_samples";
    sqlite3_bind_text(samples.get(), 1, key, -1, SQLITE_STATIC);
    if (sqlite3_step(samples.get()) != SQLITE_DONE) {
        set_error(db_, error, "学習件数を更新できません");
        rollback(db_);
        return TrainStatus::Error;
    }
    if (!exec(db_, "COMMIT", error)) {
        rollback(db_);
        return TrainStatus::Error;
    }
    return TrainStatus::Trained;
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
    Statement words(db_, "SELECT token,spam_docs,ham_docs FROM token_stats");
    if (!words.ok()) {
        set_error(db_, error, "単語統計SQLを準備できません");
        return false;
    }
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
                          "(SELECT count(*) FROM training_receipts),"
                          "(SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size())");
    if (!counts.ok() || sqlite3_step(counts.get()) != SQLITE_ROW) {
        set_error(db_, error, "DB統計を取得できません");
        return false;
    }
    stats.vocabulary_size = static_cast<std::size_t>(sqlite3_column_int64(counts.get(), 0));
    stats.training_receipts = static_cast<std::size_t>(sqlite3_column_int64(counts.get(), 1));
    stats.database_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(counts.get(), 2));
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
    if (!begin(db_, error)) return false;

    Statement rare(db_, "DELETE FROM token_stats WHERE (spam_docs+ham_docs) < ?1");
    if (!rare.ok()) { set_error(db_, error, "低頻度語削除SQLを準備できません"); rollback(db_); return false; }
    sqlite3_bind_int64(rare.get(), 1, static_cast<sqlite3_int64>(min_total_frequency));
    if (sqlite3_step(rare.get()) != SQLITE_DONE) { set_error(db_, error, "低頻度語を削除できません"); rollback(db_); return false; }

    Statement excess(db_,
        "DELETE FROM token_stats WHERE token NOT IN ("
        " SELECT token FROM token_stats ORDER BY (spam_docs+ham_docs) DESC, token ASC LIMIT ?1)");
    if (!excess.ok()) { set_error(db_, error, "語彙上限SQLを準備できません"); rollback(db_); return false; }
    const auto capped = std::min<std::size_t>(max_vocabulary,
        static_cast<std::size_t>(std::numeric_limits<sqlite3_int64>::max()));
    sqlite3_bind_int64(excess.get(), 1, static_cast<sqlite3_int64>(capped));
    if (sqlite3_step(excess.get()) != SQLITE_DONE) { set_error(db_, error, "語彙を整理できません"); rollback(db_); return false; }

    if (receipt_retention_days > 0) {
        Statement receipts(db_, "DELETE FROM training_receipts WHERE trained_utc < ?1");
        if (!receipts.ok()) { set_error(db_, error, "履歴整理SQLを準備できません"); rollback(db_); return false; }
        const auto cutoff = now_utc() - static_cast<std::int64_t>(receipt_retention_days) * 86400;
        sqlite3_bind_int64(receipts.get(), 1, cutoff);
        if (sqlite3_step(receipts.get()) != SQLITE_DONE) { set_error(db_, error, "古い履歴を整理できません"); rollback(db_); return false; }
    }
    if (!exec(db_, "COMMIT", error)) { rollback(db_); return false; }
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
