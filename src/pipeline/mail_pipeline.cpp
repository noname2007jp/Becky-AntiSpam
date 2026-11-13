#include "mail_pipeline.hpp"

#include "sha256.hpp"

#include <algorithm>
#include <cctype>

namespace beckyas {
namespace {

std::string without_classification_header(const std::string& raw_message) {
    std::size_t separator = raw_message.find("\r\n\r\n");
    if (separator == std::string::npos)
        separator = raw_message.find("\n\n");
    if (separator == std::string::npos) return raw_message;

    std::string canonical;
    canonical.reserve(raw_message.size());
    std::size_t position = 0;
    bool skip_continuation = false;
    while (position < separator) {
        auto line_end = raw_message.find('\n', position);
        if (line_end == std::string::npos || line_end >= separator)
            line_end = separator;
        const auto next = line_end < separator ? line_end + 1 : separator;
        auto line = raw_message.substr(position, line_end - position);
        if (!line.empty() && line.back() == '\r') line.pop_back();

        const bool continuation = !line.empty() &&
            (line.front() == ' ' || line.front() == '\t');
        if (!continuation) {
            const auto colon = line.find(':');
            std::string name = colon == std::string::npos
                ? std::string{} : line.substr(0, colon);
            std::transform(name.begin(), name.end(), name.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            skip_continuation = name == "x-antispam-classification";
        }

        if (!skip_continuation)
            canonical.append(raw_message, position, next - position);
        position = next;
    }
    canonical.append(raw_message, separator, raw_message.size() - separator);
    // Becky! may retain the final CRLF that was part of the SMTP terminator.
    while (!canonical.empty() &&
           (canonical.back() == '\r' || canonical.back() == '\n'))
        canonical.pop_back();
    return canonical;
}

std::string evaluation_message_hash(const std::string& raw_message) {
    return sha256_hex(without_classification_header(raw_message));
}

} // namespace

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

    // Match the receive-time prediction while excluding the annotation added by
    // this plugin. The raw-message hash keeps distinct senders/messages separate.
    const auto evaluation_hash = evaluation_message_hash(raw_message);
    if (!store_.complete_evaluation(evaluation_hash, spam, error))
        return TrainStatus::Error;

    const auto hash = sha256_hex(raw_message);
    const auto status = store_.train_once(hash, classifier_text(output.message), spam, error);
    if (status == TrainStatus::Trained || status == TrainStatus::Reclassified) {
        if (!store_.load_model(model_, error)) return TrainStatus::Error;
    }
    return status;
}

bool MailPipeline::record_prediction(const std::string& raw_message,
                                     const Result& result,
                                     std::string* error,
                                     bool include_symbol_comparison,
                                     std::uint64_t diagnostic_case) {
    if (!initialized_ && !initialize(error)) return false;
    const auto hash = evaluation_message_hash(raw_message);
    return store_.record_evaluation_prediction(
        hash, result.verdict, result.score, result.bayes_probability,
        model_.ham_samples(), model_.spam_samples(), error,
        result.symbol_comparison.verdict, result.symbol_comparison.score,
        include_symbol_comparison, diagnostic_case);
}

bool MailPipeline::label_evaluation(const std::string& raw_message,
                                      bool spam,
                                      bool* matched,
                                      std::string* error,
                                      EvaluationRecord* record) {
    if (matched) *matched = false;
    if (!initialized_ && !initialize(error)) return false;
    const auto hash = evaluation_message_hash(raw_message);
    return store_.complete_evaluation(hash, spam, error, matched, record);
}

bool MailPipeline::get_evaluation_stats(EvaluationStats& stats,
                                        std::string* error) const {
    return store_.get_evaluation_stats(stats, error);
}

} // namespace beckyas
