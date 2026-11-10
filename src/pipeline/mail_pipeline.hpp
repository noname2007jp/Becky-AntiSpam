#pragma once

#include "antispam.hpp"
#include "message_parser.hpp"
#include "sqlite_store.hpp"

#include <string>

namespace beckyas {

// Connects raw-message parsing, local classification and persistent user training.
// It never moves or deletes mail and never performs network access.
class MailPipeline {
public:
    explicit MailPipeline(SqliteStore& store,
                          Settings settings = {},
                          ParseLimits limits = {});

    bool initialize(std::string* error = nullptr);
    bool analyze(const std::string& raw_message,
                 ParsedMail& parsed,
                 Result& result,
                 std::string* error = nullptr);

    // Parses and hashes the exact raw message, then stores only classifier tokens
    // and the SHA-256 receipt. The message body/header are not persisted.
    TrainStatus train(const std::string& raw_message,
                      bool spam,
                      ParsedMail* parsed = nullptr,
                      std::string* error = nullptr);

    // Persist the pre-training prediction using a content-only classifier hash.
    bool record_prediction(const Message& message, const Result& result,
                           std::string* error = nullptr);
    bool get_evaluation_stats(EvaluationStats& stats,
                              std::string* error = nullptr) const;

    const BayesianModel& model() const noexcept { return model_; }

private:
    SqliteStore& store_;
    MessageParser parser_;
    Filter filter_;
    BayesianModel model_;
    bool initialized_ = false;
};

} // namespace beckyas
