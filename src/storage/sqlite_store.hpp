#pragma once

#include "antispam.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

struct sqlite3;

namespace beckyas {

enum class TrainStatus { Trained, Reclassified, Duplicate, Error };

struct StoreStats {
    std::size_t spam_samples = 0;
    std::size_t ham_samples = 0;
    std::size_t vocabulary_size = 0;
    std::size_t training_receipts = 0;
    std::uint64_t database_bytes = 0;
};

class SqliteStore {
public:
    explicit SqliteStore(std::string database_path, std::size_t max_vocabulary = 50000);
    ~SqliteStore();

    SqliteStore(const SqliteStore&) = delete;
    SqliteStore& operator=(const SqliteStore&) = delete;

    bool open(std::string* error = nullptr);
    void close() noexcept;
    bool is_open() const noexcept;

    // message_hash must be a lowercase or uppercase 64-character SHA-256 hex digest.
    // The caller computes it from a documented canonical message representation.
    TrainStatus train_once(const std::string& message_hash,
                           const std::string& text,
                           bool spam,
                           std::string* error = nullptr);

    bool load_model(BayesianModel& model, std::string* error = nullptr) const;
    bool get_stats(StoreStats& stats, std::string* error = nullptr) const;

    // Removes rare/excess vocabulary and receipts older than receipt_retention_days.
    bool compact(std::size_t max_vocabulary,
                 std::size_t min_total_frequency,
                 int receipt_retention_days,
                 std::string* error = nullptr);

    bool integrity_check(std::string& result, std::string* error = nullptr) const;
    bool backup_to(const std::string& destination_path, std::string* error = nullptr) const;

private:
    std::string database_path_;
    sqlite3* db_ = nullptr;
    std::size_t max_vocabulary_ = 50000;
};

} // namespace beckyas
