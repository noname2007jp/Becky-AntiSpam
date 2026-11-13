# 学習データストア設計

## 方針

SQLiteを第一候補とし、Becky!と同じWin32/x86で利用できることをCIで検証する。DBはBecky!のデータフォルダ配下に置く。本文・完全ヘッダー・添付ファイルは保存しない。

## 初期スキーマ案

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS token_stats (
    token TEXT PRIMARY KEY,
    spam_docs INTEGER NOT NULL DEFAULT 0 CHECK (spam_docs >= 0),
    ham_docs INTEGER NOT NULL DEFAULT 0 CHECK (ham_docs >= 0),
    last_seen_utc INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_token_stats_last_seen
    ON token_stats(last_seen_utc);

CREATE TABLE IF NOT EXISTS training_receipts (
    message_hash TEXT PRIMARY KEY CHECK (length(message_hash) = 64),
    label INTEGER NOT NULL CHECK (label IN (0, 1)),
    trained_utc INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_training_receipts_trained
    ON training_receipts(trained_utc);

CREATE TABLE IF NOT EXISTS address_rules (
    pattern TEXT PRIMARY KEY,
    rule_type INTEGER NOT NULL CHECK (rule_type IN (0, 1)),
    created_utc INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1))
);

CREATE TABLE IF NOT EXISTS ai_reviews (
    message_hash BLOB PRIMARY KEY,
    classification INTEGER NOT NULL CHECK (classification IN (-1, 0, 1)),
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    confirmed INTEGER NOT NULL DEFAULT 0 CHECK (confirmed IN (0, 1)),
    created_utc INTEGER NOT NULL,
    expires_utc INTEGER
);
```

## 値の定義

- `token_stats`: tokenごとの文書頻度。spam_docs/ham_docsは同一メール内で同じtokenが複数回出ても1回だけ加算する。
- `training_receipts`: 同一メールの二重学習を防ぐためのハッシュ。ハッシュは正規化したメール内容から計算し、元メール本文は保存しない。ハッシュも個人情報に準じて保護・期限管理する。
- `address_rules`: ユーザーが明示登録した安心/迷惑アドレス・ドメイン。rule_typeの意味はアプリ定数で管理する。
- `ai_reviews`: AIの仮判定。confirmed=0の間は確定教師データに利用しない。期限切れの仮判定は整理対象。
- `meta`: スキーマバージョン、トークナイザーID、辞書バージョン、最終メンテナンス時刻等。

## トランザクション

1. メールハッシュを `training_receipts` にINSERTする。
2. UNIQUE制約違反なら既存ラベルを確認し、同じラベルなら二重学習として中止、異なるラベルなら訂正として差分更新する。
3. トークンを重複排除し、`token_stats` をUPSERTする。
4. 全処理を1トランザクションで確定する。途中失敗時はROLLBACK。

## スリム化

- まず期限切れのAI仮判定・古い照会記録を削除する。
- token_statsは文書頻度とlast_seen_utcを基準に候補を選ぶ。
- 学習件数の集計と語彙削減は別々に実施し、精度評価を行う。
- training_receiptsは二重学習防止期間を過ぎたものを削除可能とする。ただし削除後は古いメールが再学習され得ることをUIで説明する。
- 削除・集約の前にDBバックアップを作成する。
- `PRAGMA integrity_check` で整合性を確認し、その後必要な場合に `VACUUM` を実行する。
- WALモードを使う場合は、バックアップ手順でWALを含む整合性を確保する。

## 未決事項

- SQLiteを同梱する方法（amalgamation / vcpkg / system package）
- Win32/x86ビルドでのSQLiteバージョンとライセンス表記
- message_hashの正規化対象とハッシュ方式
- 自動整理の実行頻度・保持期間・ユーザー通知方法
- DB暗号化の必要性。現段階では暗号化を標準要件とせず、Windows ACLとDPAPIによる秘密情報保護を優先して検討する

## 受け入れテスト

- 同一メールを2回学習しても単語頻度が二重加算されない。
- 正常・迷惑のラベル訂正がトランザクションで一貫して反映される。
- 整理前にバックアップが作成される。
- 整理後にintegrity_checkが成功する。
- DB容量・語彙数・学習件数を画面で確認できる。
- 整理前後の代表メールセットの判定結果を比較できる。

## 実装状況（SQLite永続化の初期実装）

- SQLite 3.54.1 amalgamationをCMake FetchContentで取得し、Win32/x86を含むビルド時にソースから静的リンクする。
- アーカイブは公式配布物のSHA3-256値をCMakeで検証する。
- `SqliteStore` がDB初期化、スキーマバージョン管理、WAL、学習、復元、統計、バックアップ、整合性確認、明示的な圧縮を担当する。
- 学習処理は `BEGIN IMMEDIATE` から始め、メールハッシュ登録・単語統計更新・学習件数更新を一括コミットする。
- 同じSHA-256ハッシュ・同じラベルなら `Duplicate` を返して統計を変更しない。ラベルが異なる場合は `Reclassified` として、旧ラベルの単語頻度・学習件数を減算し、新ラベルへ加算する。
- DBにはトークン別の文書頻度、学習件数、SHA-256ハッシュ、学習日時のみを保存する。本文・完全ヘッダー・添付ファイルは保存しない。
- 学習時は既定50,000語（設定可能）を基準に、上限+5%または100語を超えた時点で低頻度語から整理する。学習対象テキストは1MiBを上限とする。
- `compact()` は実行前に `.precompact.bak` へバックアップし、低頻度語・語彙上限超過分・保持期限を過ぎた学習履歴を整理した後、WALチェックポイントとVACUUMを実行する。
- 履歴保持日数に0を指定すると学習履歴の期限削除を行わない。期限削除後は古いメールが再学習される可能性がある。
- 現在の実装スキーマは `meta`、`token_stats`、`training_receipts`。`address_rules` と `ai_reviews` は設計案であり、まだ実装していない。

### 実装上の注意・次の作業

- `train_once()` に渡すハッシュは、呼び出し側で正規化ルールを固定したメール表現から計算したSHA-256（64桁16進数）とする。現在のストレージ層はハッシュ形式を検証するが、メールの正規化やSHA-256計算自体はまだ担当しない。
- 受信コールバックからのDBアクセス、Becky!データフォルダの確定、ハッシュ正規化、SQLiteエラー時のUI通知はプラグイン統合時に実装する。
- 自動VACUUMは実行時間と一時ディスク容量を要するため、受信処理中には呼ばず、ユーザー操作またはアイドル時の保守処理として実行する。
- 現段階の単体テストは永続化・重複防止・再オープン・バックアップ・整合性・圧縮を対象とする。Becky!本体との統合試験は別途必要。


## 評価結果の記録（スキーマ v3）

### 評価ラベルのみを登録する操作
- メール一覧の右クリックメニューに、学習を行わない評価専用コマンドを追加する。
- 受信時に保存した一方向ハッシュと選択メールの正規化ハッシュを照合し、該当する予測の `actual_label` だけを更新する。
- 対応する予測が存在しないメールは「予測なし」として扱い、評価件数に加えない。メール本文・ヘッダー・トークンを保存せず、Bayes学習モデルにも触れない。
- 評価用予測の保存は `evaluation.enabled=1` で制御し、詳細テストログの `test_mode` とは独立させる。

- `evaluation_results` は、`evaluation.enabled=1`（初期値ON）で受信時に記録した予測と、後からユーザーが「評価用：正常メールとして記録／迷惑メールとして記録」を実行して確定したHam/Spamラベルを対応付ける。詳細テストログのON/OFFとは独立する。
- 予測時点で、生メールの正規化ハッシュ、判定（Ham/Review/Spam）、スコア、Bayes確率、予測時点のHam/Spam学習件数、予測日時を保存する。本文・ヘッダー・トークン・送信者情報は保存しない。
- 評価用ハッシュは受信時の生メールから計算し、Becky!が後から追加する `X-AntiSpam-Classification` ヘッダーと末尾のCR/LFだけを正規化対象として除外する。From等のヘッダーも含むため、ブランド判定など送信者情報を参照するルールが異なるメールを誤って同一評価対象にまとめない。
- 手動学習時に同じハッシュの予測が存在すれば、その操作で確定したラベルを `actual_label` に記録する。予測が存在しない（機能追加前に受信したメール等）場合、通常の学習処理には影響しない。
- 評価統計は実際のラベルと予測判定の組み合わせを集計し、Spam→Ham/Review/Spam、Ham→Ham/Review/Spamの混同行列として取得する。
- 未確定の予測は30日経過後に新しい予測記録時に整理する。ラベル確定済みの評価結果は保持する。
- この方式は、ユーザーが正解ラベルを付ける直前の予測を測るオンライン評価（prequential evaluation）であり、独立したホールドアウト評価とは区別する。評価対象メールはラベル確定後に学習されるため、同じメールを学習後に再評価した精度として扱わない。
- プラグイン側では `evaluation.enabled=1` の場合に予測を記録する。評価ラベル登録操作は評価DBのみを更新し、Bayes学習DB・トークン統計を変更しない。従来の「Ham/Spamとして学習」操作は、評価ラベル確定と学習を引き続き同時に行う。
