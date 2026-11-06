# Becky AntiSpam

Becky! Internet Mail 専用の迷惑メールフィルタープラグインを開発するプロジェクトです。

## 開発方針

- 対象環境: 64bit Windows上のBecky! Internet Mail Ver.2.83.11（32bit / x86）
- プラグインDLL: Win32 / x86
- 処理モード: 自動振り分け / 手動判定を設定で切り替え
- 判定方式: ルール判定 + ベイジアン学習 + スコアリング
- プライバシー: メール本文・ヘッダー・学習データは原則ローカル保存。外部送信しない
- 安全性: 初期設定は「判定のみ」。自動移動は利用者が明示的に有効化する

## SDK確認状況

Becky! Plug-In SDKを入手し、受信前フィルター用の `BKC_OnBeforeFilter2`、受信後通知用の `BKC_OnRetrieve`、手動操作に使えるメール取得・移動APIを確認しました。詳細は [SDK調査結果](docs/SDK-ANALYSIS.md) を参照してください。

Becky!本体は32bitアプリケーションのみ提供されているため、64bit Windows上でもプラグインDLLはWin32 / x86でビルドします。GitHub ActionsもWin32構成に変更しました。

## 開発状況

- [x] 初期判定エンジンの骨格
- [x] SDK API / コールバックの一次調査
- [x] Becky! 2.83.11 / Win32(x86) を対象に確定
- [ ] 最小プラグインDLLとBecky!ロード確認
- [ ] 最小プラグインDLLとBecky!実機ロード確認
- [x] MIME/ヘッダー解析（multipart、Base64、quoted-printable、Windows日本語文字コード変換）
- [x] SHA-256ハッシュ生成（生メールの完全一致識別用）
- [ ] 日本語トークナイズ方式の検証（MeCab x86候補）
- [x] ベイジアン学習・SQLite永続化（初期実装）
- [x] 学習DBの容量管理・スリム化・バックアップ（初期API）
- [ ] 安心/迷惑リスト、手動学習・再判定
- [ ] URL/添付ファイル等の補助判定
- [ ] AI API補助判定（初期OFF・非同期・ユーザー確認後に学習）
- [ ] 自動振り分け（監査試験後）
- [ ] Windows x86 CIでDLLビルド・テスト

## 仕様・ロードマップ

- [統合機能仕様](docs/FEATURE-SPEC.md)
- [開発ロードマップ](docs/ROADMAP.md)
- [学習データストア設計](docs/DATA-STORE.md)
- [SDK調査結果](docs/SDK-ANALYSIS.md)

## 機能計画

1. MIME/ヘッダー解析
2. ルールベース判定
3. ベイジアン学習（迷惑メール / 正常メール）
4. 判定スコアと判定理由
5. 手動判定・学習操作
6. 自動振り分け（SDKで安全な移動APIを確認後）
7. Becky! Plug-In SDK に基づくWin32 DLL統合
8. GitHub Actions によるWindows x86ビルド・テスト

## ディレクトリ構成

- `src/engine`: Becky! に依存しない判定エンジン
- `src/storage`: SQLite学習データストア
- `src/parser`: RFC 5322 / MIMEメール解析
- `src/crypto`: SHA-256
- `src/plugin`: Becky! SDK アダプター
- `tests`: 単体テスト
- `config`: 初期ルール
- `.github/workflows`: Windows CI

## ビルド

CMake と Visual Studio 2022 を使用し、`-A Win32` でビルドします。Becky! SDKの実ヘッダーを使ったDLL統合は、最小プラグインのロード確認後に進めます。
