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
- [x] 監査専用Becky!プラグインDLL（Win32/x86）の実装・CIビルド
- [x] 運用ログ／テスト詳細ログの個別ON/OFF設定（初期値：運用ログON、テスト詳細OFF）
- [ ] Becky! 2.83.11でのDLLロード・受信コールバック実機確認
- [x] MIME/ヘッダー解析（multipart、Base64、quoted-printable、Windows日本語文字コード変換）
- [x] SHA-256ハッシュ生成（生メールの完全一致識別用）
- [x] 日本語フォールバックトークナイザー（UTF-8文字単位・日本語2-gram・カタカナ複合語）
- [ ] MeCab x86の任意統合（ライセンス・辞書配布条件の確認後）
- [x] ベイジアン学習・SQLite永続化（初期実装）
- [x] MIME解析→判定→SHA-256重複防止→SQLite学習の共通パイプライン
- [x] 学習DBの容量管理・スリム化・バックアップ（初期API）
- [ ] 安心/迷惑リスト、手動学習・再判定
- [ ] URL/添付ファイル等の補助判定
- [ ] AI API補助判定（初期OFF・非同期・ユーザー確認後に学習）
- [ ] 自動振り分け（監査試験後）
- [x] Windows x86 CIでDLLビルド・テスト・成果物アップロード

## 仕様・ロードマップ

- [製品仕様書](docs/SPECIFICATION.md)
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
- `src/pipeline`: 解析・判定・学習の統合
- `src/plugin`: Becky! SDK アダプター
- `tests`: 単体テスト
- `config`: 初期ルール
- `.github/workflows`: Windows CI

## ビルド

CMake と Visual Studio を使用し、`-A Win32` でビルドします。

```powershell
cmake -S . -B build -A Win32
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

DLLは `build/Release/BeckyAntiSpam.dll` に生成されます。GitHub Actionsの [Windows x86 build](https://github.com/noname2007jp/Becky-AntiSpam/actions) からも `BeckyAntiSpam-Win32` アーティファクトを取得できます。

設定GUIはWindows用の `BeckyAntiSpamConfig.exe` としてビルドされます。プラグインと同じ `%APPDATA%\\BeckyAntiSpam\\settings.ini` を編集し、現時点では通常ログ／詳細テストログのON/OFFを変更できます。設定変更後はBecky!を再起動してください。GUIはまだBecky!のメニューには統合していないため、単体で起動します。

ログ設定は `%APPDATA%\\BeckyAntiSpam\\settings.ini` で変更できます。

```ini
[logging]
enabled=1
[test_mode]
enabled=0
```

- `logging.enabled=1`: 通常ログを `operation.log` に記録（初期値ON、約5MiBでローテーション）
- `logging.enabled=0`: ファイルログをすべて停止
- `test_mode.enabled=1`: 詳細ログを `test-detail.log` に追加記録（初期値OFF、約20MiBでローテーション）
- テストモードでは解析サイズ・MIME構成・判定値・ルール名／理由・解析警告・内部エラーを記録します。メール本文、件名、送信者、ヘッダー値そのものは記録しません。

現段階のDLLは監査専用です。Becky!の `PlugIns` フォルダーへ配置してロード確認する前に、既存設定・メールデータのバックアップを推奨します。メールの移動・削除は行いません。監査ログと学習DBは `%APPDATA%\\BeckyAntiSpam\\` に作成されます。
