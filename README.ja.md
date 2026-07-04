# go-clamav

[![CI](https://github.com/PyYoshi/go-clamav/actions/workflows/ci.yaml/badge.svg)](https://github.com/PyYoshi/go-clamav/actions/workflows/ci.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/PyYoshi/go-clamav.svg)](https://pkg.go.dev/github.com/PyYoshi/go-clamav)

信頼できないユーザーアップロードを受理する前にスキャンするための、純Go製
[clamd](https://docs.clamav.net/)(ClamAVデーモン)クライアントです。型システムの
レベルから **fail-closed(判定不能時は安全側に倒す)** で設計されています。

English version: [README.md](README.md)

- **純Go・標準ライブラリのみ。** cgoなし、外部依存なし、`CGO_ENABLED=0` でビルド可能。
  clamdのソケットプロトコルを直接実装しています(libclamavをリンクしない理由は
  [ADR-0001](docs/adr/0001-clamd-socket-over-libclamav.md) を参照)。
- **INSTREAM専用。** ファイル内容をclamdへストリーミングします。clamdがスキャン対象の
  ファイルシステムへアクセスする必要はなく、一時ファイルも作成しません。
- **構造的にfail-closed。** エラーがクリーン判定と混同されることは型の上であり得ず、
  サイズ超過の入力は送信前に拒否され、解釈できない応答は推測せずエラーになります。
- **context対応。** すべての呼び出しが `context.Context` のキャンセル・デッドラインを
  ストリーミング途中でも尊重します。
- **DoS耐性。** 応答読み取りの上限、操作単位のI/Oタイムアウト、クライアント側
  サイズ上限、任意の並行数キャップを備えます。

## fail-closed契約

本ライブラリはセキュリティ制御です。呼び出し側は必ず次の規則に従ってください:

| 結果                        | 意味                             | 呼び出し側の義務               |
| --------------------------- | -------------------------------- | ------------------------------ |
| `err == nil && res.Clean()` | スキャン完了・検出なし           | ファイルを受理してよい         |
| `res.Infected()`            | スキャン完了・シグネチャ一致     | 拒否。隔離と監査ログを推奨     |
| `err != nil`(種別不問)    | **判定不能 — クリーンではない**  | 受理禁止(リトライ後も駄目なら拒否) |

`err != nil` のとき、返される `ScanResult` は常にゼロ値であり、その `Verdict` は
`VerdictUnknown` です。誤ってエラーを無視して `res.Clean()` だけを見る実装でも
ファイルが受理されることはありません。スキャン失敗(タイムアウト、接続障害、
`ErrSizeLimitExceeded` など)を「マルウェアなし」として扱わないでください。

## インストール

```
go get github.com/PyYoshi/go-clamav
```

Go 1.26以上と、稼働中のclamdが必要です。推奨デプロイ対象は1.4 LTS系
(2027-08-15までサポート)で、CIでは1.4 LTSと現行の通常リリース(1.5)を
検証しています。

## クイックスタート

```go
client, err := clamav.New("unix:///run/clamav/clamd.sock",
    clamav.WithMaxStreamSize(25<<20),    // clamdのStreamMaxLengthと同値にする
    clamav.WithMaxConcurrentScans(4),    // clamdのMaxThreadsより小さくする
)
if err != nil {
    log.Fatal(err)
}

ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
defer cancel()

result, err := client.Scan(ctx, uploadedFile)
switch {
case err != nil:
    // 判定不能: アップロードを拒否する。リトライの可否は IsRetryable を参照。
    reject(err)
case result.Infected():
    quarantine(result.Signature)
default:
    accept()
}
```

HTTPステータスの対応付けやヘルスチェックまで含む完全なアップロードエンドポイントは
[examples/httpupload](examples/httpupload/main.go)、CLIスキャナは
[examples/basicscan](examples/basicscan/main.go) にあります。

## API概要

```go
func New(addr string, opts ...Option) (*Client, error)

func (c *Client) Scan(ctx context.Context, r io.Reader) (ScanResult, error)
func (c *Client) ScanBytes(ctx context.Context, data []byte) (ScanResult, error)
func (c *Client) ScanFile(ctx context.Context, path string) (ScanResult, error)

func (c *Client) Ping(ctx context.Context) error              // readinessプローブ
func (c *Client) Version(ctx context.Context) (string, error) // シグネチャDBの版と日付を含む
func (c *Client) Stats(ctx context.Context) (string, error)   // 診断用テキスト
func (c *Client) Reload(ctx context.Context) error            // 管理用。スキャン経路で呼ばない
```

`Client` はゴルーチンセーフです。clamdの「1接続=1コマンド」というセッションモデルに
合わせ、各コマンドは専用の接続で実行されます。

### オプション

| オプション                   | デフォルト | 備考                                                          |
| ---------------------------- | ---------- | ------------------------------------------------------------- |
| `WithMaxStreamSize(n)`       | 25 MiB     | クライアント側サイズ上限。**clamdの `StreamMaxLength` と同値にすること。** `NoSizeLimit` で無効化(非推奨) |
| `WithMaxConcurrentScans(n)`  | 0(無効)  | 並行スキャン数の上限。clamdの `MaxThreads` より小さく          |
| `WithDialTimeout(d)`         | 10秒       | 接続確立のタイムアウト                                        |
| `WithIOTimeout(d)`           | 30秒       | read/write単位の無進捗上限(全体時間はcontextで制御)         |
| `WithChunkSize(n)`           | 32 KiB     | INSTREAMチャンクのペイロードサイズ                            |
| `WithDialFunc(fn)`           | net.Dialer | トランスポート差し替え(テスト・プロキシ用)                  |

### エラー

失敗は必ず次の4形態のいずれかで返ります。`errors.Is/As` で分類してください:

| エラー                 | 意味                                             | `IsRetryable` |
| ---------------------- | ------------------------------------------------ | ------------- |
| `ErrSizeLimitExceeded` | クライアント側またはclamd側のサイズ上限。**未スキャン** | いいえ   |
| `*ClamdError`          | clamdが `... ERROR` を応答                       | いいえ        |
| `*ProtocolError`       | 分類不能な応答(fail-closed)                    | いいえ        |
| `*ConnectionError`     | dial/read/writeのトランスポート障害              | はい          |
| context起因            | `context.Canceled` / `DeadlineExceeded` をラップ | いいえ / はい |

ライブラリは自動リトライを行いません。`io.Reader` は再読み込みできず、暗黙の
リトライは大きなアップロードを二重送信するためです。`IsRetryable(err)` を判定し、
入力を呼び出し側で再供給(ファイルを開き直すなど)した上で、上限付きバックオフで
リトライしてください。

## アドレスとデプロイのセキュリティ

```
unix:///run/clamav/clamd.sock   # 推奨
tcp://127.0.0.1:3310            # ループバック/隔離されたプライベートネットワーク限定
```

clamdのプロトコルは**認証なしの平文**です。アドレスはセキュリティ上重要な
デプロイ設定として扱ってください:

- Unixソケットを優先する。TCPはループバックか隔離ネットワークのみ。
- clamdのポートを信頼できないネットワークに公開しない(到達できる者は
  `SHUTDOWN` コマンドも発行できます)。
- アドレスをリクエストやユーザー入力から導出しない(SSRF型の踏み台化防止)。
- スキームなしのアドレスは `New` が意図的に拒否します。

運用面のハードニング(clamd.confの制限値、freshclam、シグネチャ鮮度の監視、
過負荷時の挙動)は [docs/operations.md](docs/operations.md) を参照してください。

## テスト

```
make test          # ユニットテスト+レース検出(Docker不要)
make integration   # Docker上のclamdを起動して統合テストを実行
make fuzz          # 応答パーサの短時間ファジング
make lint          # golangci-lint(セキュリティ強め設定)+ govulncheck
make format        # gofumpt + gci による整形(golangci-lint fmt経由)
```

統合テスト環境([docker/](docker/))は、EICARのみの極小シグネチャDBを使って公式
`clamav/clamav` イメージを数秒で起動し、Unixソケットとループバック TCP の両方を
公開し、サイズ上限パスを実際に検証できるよう小さな `StreamMaxLength` を設定して
います。EICARテスト文字列は、リポジトリ内では完全な形で存在しません — hex表記の
シグネチャと分割された文字列定数として保持され、テスト実行時のメモリ上でのみ
組み立てられます(チェックアウトが常駐AVに隔離される事故の防止)。

## アーキテクチャ上の位置付け

本ライブラリは
[GoogleCloudPlatform/docker-clamav-malware-scanner](https://github.com/GoogleCloudPlatform/docker-clamav-malware-scanner)
と同じパターンにおける「スキャンクライアント」部分です: アップロードは未スキャン
領域に置かれ、ワーカーがスキャンし(本ライブラリ → clamd)、結果に応じてクリーン
ストレージまたは隔離先へ振り分けます。clamdはサイドカーまたは専用サービスとして
稼働させ、freshclamはアプリケーションではなくclamdの隣で動かしてください。

## ライセンス

MIT — [LICENSE](LICENSE) を参照。本ライブラリはClamAVとソケット越しに通信し、
libclamavをリンクしません。ClamAV自体のライセンスはGPLv2のままです。
