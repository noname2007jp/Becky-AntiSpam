# Becky AntiSpam

Becky! Internet Mail 専用の迷惑メールフィルタープラグインを開発するプロジェクトです。

## 開発方針

- 対象環境: 64bit Windows上のBecky! Internet Mail Ver.2.83.11（32bit / x86）
- プラグインDLL: Win32 / x86
- AI判定エンジン: Windows x64の別プロセス（ローカル名前付きパイプで接続）
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
- [x] Becky!「ツール → プラグインの設定」から開く設定ダイアログ（初期版・CI/実機確認待ち）
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
- [x] 32bitプラグイン／64bit AIワーカー間のローカルIPCプロトコル骨格
- [ ] AIワーカーのONNX Runtime統合・日本語Tokenizer統合
- [ ] Ham/Spam教師データでFine-tuningしたモデルの評価・同梱
- [ ] Review判定からAIワーカーへの連携・タイムアウト／障害時フォールバック

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
- `src/plugin`: Becky! SDK アダプター（Win32/x86）
- `src/ai`: AIワーカー（x64）とIPCプロトコル
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

設定画面はBecky!本体の `ツール → プラグインの設定 → Becky AntiSpam` から開きます。設定画面には実際に使用しているデータ保存先が表示され、「フォルダーを開く」と「移行方法」を利用できます。変更できる設定は通常ログ／詳細テストログのON/OFFです。

ログ設定は、設定画面に表示されるデータ保存先の `settings.ini` で管理します。ブランド照合ルールは同じフォルダーの `brand-domains.txt` で管理します。

```ini
[logging]
enabled=1
[test_mode]
enabled=0
```

- `logging.enabled=1`: 通常ログを `operation.log` に記録（初期値ON、約5MiBでローテーション）
- `logging.enabled=0`: ファイルログをすべて停止
- `test_mode.enabled=1`: 詳細ログを `test-detail.log` に追加記録（初期値OFF、約20MiBでローテーション）
- `brand-domains.txt` はUTF-8の1行1ルール形式です。`別名1;別名2|許可ドメイン1;許可ドメイン2` と記載します。初回起動時にAmerican Expressの初期ルールを作成します。許可ドメインは完全一致またはそのサブドメインを許可します。
- ブランド名がSubjectまたはFrom表示名に含まれ、Fromドメインが許可ドメインと一致しない場合は `brand.domain_mismatch` を加点します。本文URLも不一致の場合は `brand.url_domain_mismatch` を加点し、Fromドメインがブランド名に類似する場合は `brand.lookalike_domain` を加点します。
- テストモードでは解析サイズ・ヘッダー数・件名／分類用ヘッダー／本文のバイト数・URL数・MIME構成・添付数・判定値・ルール名／理由・解析警告数を記録します。メール本文、件名、送信者、ヘッダー値そのもの、URLそのものは記録しません。詳細ログは `test-detail.log` に加え、`operation.log` に `[TEST]` 付きで記録します。

現段階のDLLは監査専用です。Becky!の `PlugIns` フォルダーへ配置してロード確認する前に、既存設定・メールデータのバックアップを推奨します。メールの移動・削除は行いません。設定・学習DB・ログは設定画面に表示されるデータ保存先へ作成されます。


### 設定・学習データの保存場所

設定・学習DB・ログは Becky! 本体の実行ファイルがあるフォルダーを基準に、`Plugins\\BeckyAntiSpam\\` へ保存します。PC移行時はこのフォルダーを新PCの同じ場所へコピーしてください。初回起動時に旧保存先 `%APPDATA%\\BeckyAntiSpam\\` が存在し、新保存先に同名ファイルがない場合は自動コピーします。旧データは削除しません。保存先に書き込み権限が必要です（Program Files配下など権限制限のある場所では注意してください）。


### 保存先と書き込み権限

保存先はまず Becky! 実行ファイルのある場所の `Plugins\\BeckyAntiSpam\\` を使用します。Windowsの保護された場所（例: `C:\\Program Files\\`）で書き込み権限がない場合、管理者権限を要求せず、ユーザーの `%APPDATA%\\BeckyAntiSpam\\` に自動的に切り替えます。設定画面には実際に使用している保存先が表示されます。

### PC移行方法

設定画面の「移行方法」ボタンで手順を確認できます。移行元・移行先のBecky!を完全に終了し、移行元の `BeckyAntiSpam` フォルダー全体をコピーして、移行先PCの設定画面に表示されたデータ保存先へ上書きコピーします。SQLiteはWALモードを使用するため、コピー時にBecky!が起動していないことが重要です。移行先に既存データがある場合は、事前に別の場所へ退避してください。インポート／エクスポート機能は設けず、フォルダーコピーで移行します。


### ローカルAIエンジン（開発中）

AI判定はBecky!本体と同じプロセスに組み込まず、64bitの `AntiSpamAI.exe` として分離します。Becky!側DLLは32bitのまま維持し、Windows名前付きパイプでローカル接続します。名前付きパイプはリモート接続を拒否し、メールの外部送信は行いません。

IPCではRFC822生メール全体を渡さず、必要な件名・本文のUTF-8テキストだけを送る設計です。現在のコミットではプロトコルとワーカーの起動基盤を用意した段階であり、AI推論はまだ無効です。ONNXモデル、Tokenizer、学習済み分類ヘッドの検証が完了するまで、既存のルール／Bayes判定を変更しません。

Win32 DLLとx64ワーカーは別々のCMake構成でビルドします。

```powershell
# Becky! plugin (32-bit)
cmake -S . -B build -A Win32
cmake --build build --config Release

# AI worker (64-bit)
cmake -S . -B build-x64 -A x64
cmake --build build-x64 --config Release
```
