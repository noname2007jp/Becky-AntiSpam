# 学習データストア設計

## 方針

SQLiteを第一候補とし、Becky!と同じWin32/x86で利用できることをCIで検証する。DBはBecky!のデータフォルダ配下に置く。本文・完全ヘッダー・添付ファイルは保存しない。

## 初期スキーマ案

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
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
    message_hash BLOB PRIMARY KEY,
    label INTEGER NOT NULL CHECK (label IN (0, 1)),
    trained_utc INTEGER NOT NULL,
    source INTEGER NOT NULL DEFAULT 0
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
2. UNIQUE制約違反なら二重学習として処理を中止する。
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
