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

    // The classifier hash excludes transport/identity headers and the plugin's
    // X-AntiSpam-Classification annotation, so it matches the pre-filter prediction.
    const auto evaluation_hash = sha256_hex(classifier_text(output.message));
    if (!store_.complete_evaluation(evaluation_hash, spam, error))
        return TrainStatus::Error;

    const auto hash = sha256_hex(raw_message);
    const auto status = store_.train_once(hash, classifier_text(output.message), spam, error);
    if (status == TrainStatus::Trained || status == TrainStatus::Reclassified) {
        if (!store_.load_model(model_, error)) return TrainStatus::Error;
    }
    return status;
}

bool MailPipeline::record_prediction(const Message& message,
                                     const Result& result,
                                     std::string* error) {
    if (!initialized_ && !initialize(error)) return false;
    const auto hash = sha256_hex(classifier_text(message));
    return store_.record_evaluation_prediction(
        hash, result.verdict, result.score, result.bayes_probability,
        model_.ham_samples(), model_.spam_samples(), error);
}

bool MailPipeline::get_evaluation_stats(EvaluationStats& stats,
                                        std::string* error) const {
    return store_.get_evaluation_stats(stats, error);
}

} // namespace beckyas
