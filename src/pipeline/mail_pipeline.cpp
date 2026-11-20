#include "mail_pipeline.hpp"

#include "sha256.hpp"

namespace beckyas {

MailPipeline::MailPipeline(SqliteStore& store, Settings settings, ParseLimits limits)
    : store_(store), parser_(limits), filter_(settings) {}

bool MailPipeline::initialize(std::string* error) {
    if (!store_.is_open() && !store_.open(error)) return false;
    if (!store_.load_model(model_, error)) return false;
    initialized_ = true;
    return true;
}

bool MailPipeline::analyze(const std::string& raw_message,
                           ParsedMail& parsed,
                           Result& result,
                           std::string* error) {
    if (!initialized_ && !initialize(error)) return false;
    if (!parser_.parse(raw_message, parsed, error)) return false;
    result = filter_.classify(parsed.message, &model_);
    return true;
}

TrainStatus MailPipeline::train(const std::string& raw_message,
                                bool spam,
                                ParsedMail* parsed,
                                std::string* error) {
    if (!initialized_ && !initialize(error)) return TrainStatus::Error;

    ParsedMail local;
    ParsedMail& output = parsed ? *parsed : local;
    if (!parser_.parse(raw_message, output, error)) return TrainStatus::Error;

    const auto hash = sha256_hex(raw_message);
    const auto status = store_.train_once(hash, classifier_text(output.message), spam, error);
    if (status == TrainStatus::Trained || status == TrainStatus::Reclassified) {
        if (!store_.load_model(model_, error)) return TrainStatus::Error;
    }
    return status;
}

bool MailPipeline::evaluate(const std::string& raw_message,
                            bool spam,
                            std::string* error) {
    if (!initialized_ && !initialize(error)) return false;
    if (raw_message.empty() || raw_message.size() > 5u * 1024u * 1024u) {
        if (error) *error = "評価対象メールのサイズが不正です";
        return false;
    }
    return store_.set_evaluation_label(sha256_hex(raw_message), spam, error);
}

} // namespace beckyas
