#include "antispam.hpp"
#include "sqlite_store.hpp"

#include <filesystem>

#include <cassert>
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
    model.decay(1.0); // invalid factor is ignored
    assert(model.spam_samples() == unchanged);
    std::cout << "All Becky AntiSpam engine tests passed.\n";
    return 0;
}
