# Becky AntiSpam

Becky! Internet Mail 専用の迷惑メールフィルタープラグインを開発するプロジェクトです。

## 開発方針

- 対象: 64bit Windows上で動作するBecky!（プラグインDLLはBecky!本体と同じビット数）
- 処理モード: 自動振り分け / 手動判定を設定で切り替え
- 判定方式: ルール判定 + ベイジアン学習 + スコアリング
- プライバシー: メール本文・ヘッダー・学習データは原則ローカル保存。外部送信しない
- 安全性: 初期設定は「判定のみ」。自動移動は利用者が明示的に有効化する

## SDK確認状況

Becky! Plug-In SDKを入手し、受信前フィルター用の `BKC_OnBeforeFilter2`、受信後通知用の `BKC_OnRetrieve`、手動操作に使えるメール取得・移動APIを確認しました。詳細は [SDK調査結果](docs/SDK-ANALYSIS.md) を参照してください。

SDKのサンプルプロジェクトはWin32構成のみです。64bit Windows上で32bit版Becky!を使う場合はx86 DLLが必要です。Becky!本体のビット数を実機確認するまでは、x64 DLL対応を確定扱いにしません。

## 開発状況

- [x] 初期判定エンジンの骨格
- [x] SDK API / コールバックの一次調査
- [ ] 最小プラグインDLLとBecky!ロード確認
- [ ] MIME/ヘッダー解析
- [ ] ベイジアン学習の永続化
- [ ] 手動判定・学習操作
- [ ] 自動振り分け
- [ ] Windows CIでDLLビルド・テスト

## 機能計画

1. MIME/ヘッダー解析
2. ルールベース判定
3. ベイジアン学習（迷惑メール / 正常メール）
4. 判定スコアと判定理由
5. 手動判定・学習操作
6. 自動振り分け（SDKで安全な移動APIを確認後）
7. Becky! Plug-In SDK に基づくDLL統合
8. GitHub Actions によるWindowsビルド・テスト

## ディレクトリ構成

- `src/engine`: Becky! に依存しない判定エンジン
- `src/plugin`: Becky! SDK アダプター
- `tests`: 単体テスト
- `config`: 初期ルール
- `.github/workflows`: Windows CI

## ビルド

CMake と Visual Studio 2022 を使用します。Becky!本体のビット数確認後、プラグインDLLのターゲットアーキテクチャを確定します。
