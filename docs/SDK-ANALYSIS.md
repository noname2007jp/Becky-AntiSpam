# Becky! Plug-In SDK 調査結果

## 対象資料

アップロードされた `B2PinSDK-26400.zip` の以下を確認した。

- `PlugInSDK/PlugInSDK.txt`
- `PlugInSDK/BeckyApi.h`
- `PlugInSDK/BeckyAPI.cpp`
- `PlugInSDK/Template.cpp`
- `PlugInSDK/Template.def`
- `PlugInSDK/BkPGP/BkPGP.vcproj` / `BkPGP.def`

このSDKにはプラグインのサンプル、APIラッパー、コールバック定義が含まれている。したがって、Becky!専用DLLとして実装するための基本インターフェースは確認できた。

## 重要なコールバック

### `BKC_OnBeforeFilter2` — 自動判定の本命

受信メールがフィルタリングされる直前に呼ばれる。

```cpp
int WINAPI BKC_OnBeforeFilter2(
    LPCSTR lpMessage,
    LPCSTR lpMailBox,
    int* lpnAction,
    char** lppParam
);
```

- `lpMessage`: メールソース全体。終端は `<CRLF>.<CRLF>`。
- `lpMailBox`: 受信中のメールボックスID。
- `lpnAction`: 実行するフィルターアクション。
- `lppParam`: アクションに渡すパラメーター。
- 戻り値 `BKC_FILTER_DEFAULT`: Becky!標準ルールを通常どおり適用。
- 戻り値 `BKC_FILTER_PASS`: プラグインのルールを適用した後、標準ルールも適用。
- 戻り値 `BKC_FILTER_DONE`: 標準ルールを適用しない。
- 戻り値 `BKC_FILTER_NEXT`: 他のルール追加のため、コールバックを再度呼び出すよう要求。

移動アクションは `ACTION_MOVEFOLDER`（値 0）。パラメーターはフォルダIDで、同一メールボックス内のフォルダは `\\FolderName\\` 形式を指定できる。

**実装方針:** 初期設定ではアクションを変更せず判定結果の記録だけを行う。自動振り分けが有効で、判定スコアが閾値を超えた場合だけ迷惑メールフォルダへの移動を返す。標準フィルターとの優先順位・`lppParam` のメモリ所有権は実機テストで確認する。

### `BKC_OnRetrieve` — 受信後の通知

```cpp
int WINAPI BKC_OnRetrieve(LPCTSTR lpMessage, LPCTSTR lpMailID);
```

メールが受信され、フォルダに保存されたときに呼ばれる。メールソースと新しいメールIDを受け取る。保存後の学習・記録用途の候補だが、自動振り分けの主処理には受信前の `BKC_OnBeforeFilter2` を優先する。

### 手動判定用のメニュー

`BKC_OnMenuInit` でメニューを初期化し、`CBeckyAPI::RegisterCommand` でコマンドを登録できる。選択メールは `GetNextMail(..., TRUE)` で列挙できる。

## 確認できたAPI

| API | 用途 | 備考 |
|---|---|---|
| `GetSource(mailID)` | メールの生ソース取得 | デコード前。戻り値はコールバック終了時に無効化されるため、必要なら `Free()` |
| `GetSize(mailID)` | メールサイズ取得 | Ver.2.43以降。任意APIのためNULL確認が必要 |
| `GetNextMail(..., TRUE)` | 選択メールの列挙 | 手動判定対象の取得 |
| `MoveMessages(folderID, mailIDSet, FALSE)` | 指定メールを移動 | Ver.2.50以降。複数IDは `|` 区切り |
| `MoveSelectedMessages(folderID, FALSE)` | 選択メールを移動 | 選択状態に依存 |
| `GetStatus(mailID)` | 既読等の状態取得 | MESSAGE_* フラグ |
| `ProcessMail(...)` | 一部のフィルター操作 | フォルダ移動は列挙されたアクションに含まれない |
| `GetDataFolder()` / `GetTempFolder()` | データ・一時フォルダ取得 | 設定や一時ファイルの配置候補 |

`GetSource` の戻り値はMIMEデコード前の完全なメールソース。解析エンジン側でヘッダー・MIME・本文を扱う。

## プラグインDLLの要件

- DLLはBecky!本体またはデータフォルダ配下の `PlugIns\\` に配置する。
- `BKC_OnPlugInInfo` は必須。少なくとも `szPlugInName` と `szVendor` を設定しないと、Becky!がプラグインを無視する。
- コールバックは `Template.def` のEXPORTS定義に従ってエクスポートする。
- SDKは `CBeckyAPI` をプラグインモジュール内に1インスタンスだけ持つ設計。
- メールの文字列長を固定長と仮定しない。SDK文書も動的バッファを推奨している。
- Becky!が読み込むDLLはPlugIns直下に置く。関連ファイルはサブフォルダに分けられる。

## 32bit / 64bit の整理

アップロードされたSDKのサンプルプロジェクトは Visual Studio 2005形式で、構成は `Release|Win32` と `Debug|Win32` のみ。x64構成、x64 ABI、x64用SDKヘッダーの記載は見当たらない。

プラグインDLLはロードするBecky!本体と同じビット数でなければならない。64bit Windows上で32bit版Becky!を使用する場合、プラグインもWin32/x86 DLLとしてビルドする。**「64bit Windows対応」と「x64 DLL」は別の意味**である。

公式サイトの製品説明はWindows対応を案内しているが、今回確認した公式SDK資料だけではBecky!本体のビット数を断定できない。公開されている互換性資料ではBecky!は32bit版のみの検証とされているため、実装ターゲットは当面Win32/x86を第一候補とし、利用者のBecky!実行ファイルのビット数を実機で確認して確定する。x64 DLLを先に作ることはしない。

## 実装上の注意・未確定事項

1. SDKヘッダーには `LPCTSTR` と `LPCSTR` が混在する。文字セット設定をサンプルに合わせ、実際の引数型・文字コードをビルドと実機で検証する。
2. `BKC_OnBeforeFilter2` の `lppParam` が要求するバッファの確保方法・寿命は、ヘルプ記述だけでは確定できない。SDKサンプルと実機で確認してから実装する。
3. コールバック内で処理できる時間、スレッド条件、例外をDLL境界の外へ漏らさない方法を確認する。
4. メールソースはサイズ上限を決めて安全に処理し、過大メールや不正MIMEでBecky!を停止させない。
5. メール本文・ヘッダー・学習情報を外部送信しない。

## 監査専用DLLの初期実装

`src/plugin/plugin.cpp` と `BeckyAntiSpam.def` に、以下のコールバックを実装した。

- `BKC_OnPlugInInfo`: プラグイン名・ベンダー・バージョン・説明を返す。
- `BKC_OnStart` / `BKC_OnExit`: ローカルDBと処理パイプラインを初期化・解放する。
- `BKC_OnBeforeFilter2`: メールを解析・判定し、判定結果とスコアだけを監査ログへ記録する。
- フィルター戻り値は常に `BKC_FILTER_DEFAULT`。アクションは `ACTION_NOTHING` とし、Becky!標準ルールを変更しない。
- 学習DBと監査ログは `%APPDATA%\\BeckyAntiSpam\\` に保存する。監査ログは判定区分・スコア・Bayes確率のみで、本文・件名・差出人を記録しない。
- 監査ログは約1MiBで1世代ローテーションする。
- 受信コールバック内の例外を外へ伝播させない。

これは最小の監査用実装であり、Becky! 2.83.11でのDLLロード、コールバック発火、受信処理への影響は未検証。自動移動・削除・外部通信は実装していない。

## 次の実装順

1. Becky! 2.83.11（x86）とWin32 DLLの組み合わせで実機ロードを確認。
2. `BKC_OnPlugInInfo` / `BKC_OnStart` / `BKC_OnExit` がBecky!から呼び出されることを確認。
3. `BKC_OnBeforeFilter2` の発火、メール受信時間、標準フィルターとの共存を監査モードで確認。
4. 判定結果をBecky!画面から確認できる表示・手動メニューを実装。
5. 手動学習・選択メール一括処理を実装。
6. 自動移動は誤判定率・実機試験・明示設定を満たした後に別途実装。削除機能は追加しない。


## 対象Becky!バージョン

利用者の動作確認環境は **Becky! Internet Mail Ver.2.83.11** とする。

SDKのサンプルは古いVisual Studio形式であり、Becky! Ver.2.80以降では開発環境の変更により一部プラグインが動作しなくなったとの公式告知がある。このため、SDK APIが存在することと、当該バージョンで正常ロード・動作することを分けて検証する。

### 2.83.11での確認項目

1. Becky!本体の実際のビット数を確認し、同じアーキテクチャでDLLをビルドする。
2. `BKC_OnPlugInInfo` など必須エクスポートを持つ最小DLLを配置する。
3. Becky!起動時にプラグインが認識されるか確認する。
4. 初期化・終了コールバックが呼ばれるか確認する。
5. 受信テストメールで `BKC_OnBeforeFilter2` が呼ばれるか確認する。
6. 監査モードでメール受信・標準フィルターに影響しないことを確認する。

現時点ではVer.2.83.11との実機互換性は未検証であり、確認済みとは扱わない。


## 確定したビルドターゲット

利用者から、Becky! Internet Mail Ver.2.83.11 は **32bitアプリケーション（x86）のみ提供**との確認を得た。したがって、開発ターゲットを **Windows x64 OS + Becky! x86 + プラグインDLL Win32/x86** に確定する。DLLをx64でビルドしてはならない。

GitHub Actionsの構成もVisual Studioの `-A Win32` を指定するWindows x86ビルドへ変更する。これは判定エンジンのビルド確認であり、SDKを使ったプラグインDLLのロード・動作確認が完了したことを意味しない。
