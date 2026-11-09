# 2026-11-09 判定解析・診断改善

## 変更点

### 1. 解析メタデータの可視化
詳細テストログに次の情報を追加しました。

- 元メールのバイト数
- ヘッダー数
- 件名・分類対象ヘッダー・本文の各バイト数
- URL検出数（URL文字列自体は記録しない）
- MIMEパート数
- 添付ファイル数
- 解析警告数
- 本文の切り詰め有無

メール本文、件名、送信者、ヘッダー値、URL、トークンはログに出力しません。
詳細ログが有効な場合、`operation.log` にも `[TEST]` 接頭辞付きで出力します。

### 2. 分類対象ヘッダーの欠落を修正
これまで `classifier_text()` は `Message.headers` を参照していましたが、MIMEパーサーがこのフィールドを設定していませんでした。
そのため、ヘッダー内にあるURL等がルール判定・Bayes学習の対象になっていませんでした。

`List-Unsubscribe`、`Content-Type`、`Content-Transfer-Encoding`、`X-Mailer`、`Precedence`、`Importance`、`Priority`、`X-Priority` のみを分類対象ヘッダーとして追加します。
From/To/Cc、Return-Path、Received、Message-ID、Authentication-Results など、個人識別情報や信頼できない認証情報は分類対象ヘッダーに含めません。

### 3. URL検出の正規表現を修正
`www.` のドットを誤ってエスケープしていたため、`www.example.com` 形式のURLをURL数として数えられませんでした。
正しいドットのエスケープに修正しました。

### 4. 日本語の誘導表現を補完
「アカウント情報を更新」「支払い情報を確認」など、既存の固定フレーズに一致しない表現でも、操作を促す語句とURLが同時に存在する場合にReview相当のスコアを加算します。
「ログイン」等の単語だけ、または通常の案内文だけでは加点しないテストを追加しました。

## テスト

`tests/engine_tests.cpp` に以下を追加しました。

- 分類対象ヘッダーが `Message.headers` に反映されること
- 認証結果ヘッダーや送信者アドレスを分類対象ヘッダーに含めないこと
- 日本語のアカウント操作誘導とURLの組み合わせをReviewにすること
- 一般的なログイン案内だけではHamのままであること
- `www.` URLを4件検出し、複数URLルールが発火すること

Linux上のg++でエンジン・SQLite・パイプライン・テストを直接コンパイルし、`antispam_tests` を実行しました。
結果: `All Becky AntiSpam engine and storage tests passed.`

Windows / Win32 Becky! DLLのビルドおよびBecky!実機動作は、この環境では実施していません。利用者環境でのWin32ビルドと実メールによる確認が必要です。
