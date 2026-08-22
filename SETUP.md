# Setup Guide

SafeHouse is a prompt-injection-resistant agent pipeline. This guide covers installation, Google authentication, and running tasks.

## Prerequisites

- **Python 3.12 or newer** with `venv` available
- **An Anthropic API key** — the planner and the Tier 2 processor both call the Anthropic API in-process. There is no Claude Code CLI / `claude` binary to install.
- **A Google account**, for tasks that read Gmail or Google Calendar, or send email

## Installation

The recommended way is [uv](https://docs.astral.sh/uv/), which downloads a matching Python 3.12 and builds the venv in one step — no system interpreter or manual pip upgrade needed:

```bash
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e ".[dev]"    # drop [dev] if you don't need the tests
uv run pytest tests/ -v       # no API keys required
```

Note: uv-created venvs don't ship `pip` by default — use `uv pip install ...` for further installs.

No uv? Use the stdlib `venv` — but point at Python 3.12+ explicitly (bare `python3` is often older) and upgrade pip first, since editable installs need pip >= 21.3:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

If `python3.12` is not found, install it first (macOS: `brew install python@3.12`).

## Google access token (Gmail + Calendar)

All tasks that touch email or calendar authenticate against the Gmail and Google Calendar REST APIs with an OAuth 2.0 access token. The quickest way to mint one is Google's OAuth Playground.

Access tokens expire after roughly one hour. If a task fails with `401 Unauthorized`, mint a new token and re-export `GOOGLE_ACCESS_TOKEN`.

### Auth modes (`safehouse configure`)

`safehouse configure` stores your Google auth choice in the resolved config file (see [Configuration](#configuration) for path rules). Three modes trade convenience against setup cost:


| Mode            | How it works                                                                                                   | Re-auth cadence                                                                                                                                    |
| --------------- | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `static`        | Paste an access token (see below). Simplest.                                                                   | Re-mint + reconfigure every ~1 hour.                                                                                                               |
| `token_command` | A command whose stdout is a fresh token (e.g. `oauth2l`, or your own script).                                  | Whatever your broker does. **Not** `gcloud auth print-access-token` — those tokens cannot carry Gmail/Calendar scopes (`403 insufficient scopes`). |
| `oauth`         | Refresh-token flow; `safehouse` refreshes automatically via `google-auth` (`pip install 'safehouse[google]'`). | See the expiry reality below.                                                                                                                      |




### Mint a token with the OAuth Playground

1. Open the [OAuth 2.0 Playground](https://developers.google.com/oauthplayground).
2. In **Step 1** (left panel), select the following scopes:

  | API                    | Scope                                          |
  | ---------------------- | ---------------------------------------------- |
  | Gmail API v1           | `https://www.googleapis.com/auth/gmail.modify` |
  | Gmail API v1           | `https://www.googleapis.com/auth/gmail.send`   |
  | Google Calendar API v3 | `https://www.googleapis.com/auth/calendar`     |

   `gmail.modify` covers reading and labelling mail, so a separate `gmail.readonly` scope is not needed.
3. Click **Authorize APIs**, sign in with your Google account, and grant access.
4. Click **Exchange authorization code for tokens**.
5. Copy the **Access token** (it starts with `ya29`).
6. Export it in your shell:
  ```bash
   export GOOGLE_ACCESS_TOKEN=ya29...
  ```



## Configuration

The recommended way is `safehouse configure`, which stores settings in the
config file (created `chmod 600`) and prints its path:

```bash
safehouse configure          # prompts for API key, Google token, and defaults
safehouse configure --show   # print current settings (secrets redacted)
```

Config path resolution: `$SAFEHOUSE_CONFIG` if set, else `~/.safehouse/config.toml`
if it already exists (back-compat), else `$XDG_CONFIG_HOME/safehouse/config.toml`
(default `~/.config/safehouse/config.toml`) for fresh installs. `google_credentials.json`
(oauth mode) sits next to whichever `config.toml` is in use.

Precedence is **CLI flag > environment variable > config file** — env vars
still work and override the file, which is convenient for CI and containers
(they never touch the config file, so its permission check does not apply):

```bash
# Required for all tasks
export ANTHROPIC_API_KEY=sk-ant-...

# Required for any task that reads mail/calendar or sends email.
# Expires hourly — see "Google access token" above.
export GOOGLE_ACCESS_TOKEN=ya29...

# Where results, summaries, and confirmations are emailed.
# Optional: can be overridden per run with --recipient; if neither is set,
# tasks that need it will prompt at runtime.
export DEMO_RECIPIENT=you@example.com
```


| Variable                         | Required by                                      | Notes                                                                              |
| -------------------------------- | ------------------------------------------------ | ---------------------------------------------------------------------------------- |
| `ANTHROPIC_API_KEY`              | All tasks                                        | Planner and in-process Tier 2 processor                                            |
| `GOOGLE_ACCESS_TOKEN`            | Tasks that use Gmail or Calendar                 | From the OAuth Playground; expires after ~1 hour                                   |
| `DEMO_RECIPIENT`                 | Tasks that email their output                    | Optional — overridden by `--recipient`; prompted at runtime if neither is set      |
| `DUFFEL_ACCESS_TOKEN`            | Flight search / `book_flight`                    | Duffel → Developers → Access tokens. Use a **test-mode** token (`duffel_test_…`)   |
| `LITEAPI_SANDBOX_KEY`            | Hotel search / `book_hotel`                      | liteapi.travel dashboard → API Keys. Use a **sandbox** key (`sand_…`)              |
| `GITHUB_TOKEN`                   | GitHub issue/PR read, comment, or review         | PAT; `public_repo` or `repo`. Prefer `safehouse configure`                         |
| `SAFEHOUSE_MIN_GITHUB_INTEGRITY` | Optional GitHub provenance floor                 | `merged` > `approved` > `unapproved` > `none` > `blocked`; unset disables the gate |
| `SAFEHOUSE_MAX_BOOKING`          | Optional booking spend ceiling                   | e.g. `300 GBP`                                                                     |

> **`book_flight` and `book_hotel` make real bookings.** They call the live Duffel and
> LiteAPI endpoints, so a production credential means a real reservation against a real
> payment method. Nothing verifies that a key is test-mode, and the spend ceiling is only
> enforced when set. SafeHouse is a research prototype: the booking tools exist to
> exercise the enforcement model end to end, not as a production booking client.

## Usage

Describe the task in plain language. SafeHouse plans it against a fixed, validated tool set and detects the pipeline type from the resulting plan. The tool set is intentionally closed: every step is schema-validated and policy-gated before any I/O. Tasks that cannot be expressed with the supported tools are rejected at planning time with exit code `3`:

```bash
safehouse "..."                 # task as a positional argument (primary form)
safehouse --task "..."          # equivalent; --task is kept for back-compat
safehouse run - < task.txt      # read the task from stdin (or: echo "..." | safehouse run -)
```

No mode or pipeline flag is needed. `safehouse --version` prints the version;
`safehouse configure` manages credentials (see Configuration above).

### Example tasks

**Security briefing** — fetch articles, email a summary via Gmail.
Needs: `ANTHROPIC_API_KEY`, `GOOGLE_ACCESS_TOKEN`, `DEMO_RECIPIENT`

```bash
safehouse --task "Fetch these two articles and email a briefing to you@example.com: <url1> <url2>"
```

**Trip planning** — search flights and hotels, email the best options.
Needs: `ANTHROPIC_API_KEY`, `GOOGLE_ACCESS_TOKEN`, `DEMO_RECIPIENT`, `DUFFEL_ACCESS_TOKEN`, `LITEAPI_SANDBOX_KEY`

```bash
safehouse --task "Find flights LHR→LIS on 2026-08-01, hotel 3 nights, email the best combination"
```

**Email reply** — read an inbound message, draft a reply, send it via the Gmail API.
Needs: `ANTHROPIC_API_KEY`, `GOOGLE_ACCESS_TOKEN`

```bash
safehouse --task "Reply to the latest email from sender@example.com"
```

**Email summary** — recipient taken from `DEMO_RECIPIENT`, subject inferred by the agent.
Needs: `ANTHROPIC_API_KEY`, `GOOGLE_ACCESS_TOKEN`, `DEMO_RECIPIENT`

```bash
safehouse --task "Find all my invoice emails and summarise them"
```

**Email labelling** — apply a Gmail label without reading message content.
Needs: `ANTHROPIC_API_KEY`, `GOOGLE_ACCESS_TOKEN`

```bash
safehouse --task "Find all emails from sender@example.com and add the 'work' label"
```

**Calendar summary** — read today's events, email a summary.
Needs: `ANTHROPIC_API_KEY`, `GOOGLE_ACCESS_TOKEN`, `DEMO_RECIPIENT`

```bash
safehouse --task "Fetch my calendar events for today and send a summary to you@example.com"
```

**Meeting scheduling** — read a meeting request and your calendar, propose slots, create the invite.
Needs: `ANTHROPIC_API_KEY`, `GOOGLE_ACCESS_TOKEN`

```bash
safehouse --task "Read the latest meeting request from sender@example.com and schedule a 30-minute meeting next week."
```

**GitHub comment** — read an issue, draft a reply, post it after confirmation.
Needs: `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`

```bash
safehouse --task "Comment on issue 42 in owner/repo summarising the discussion"
```

**Travel audit** — read past and future calendar events, summarise total time away from home.
Needs: `ANTHROPIC_API_KEY`, `GOOGLE_ACCESS_TOKEN`, `DEMO_RECIPIENT`

```bash
safehouse --task "Find all my travel dates that are coming in the future and past and give me a summary of total time spent away from home."
```



### Command-line reference

All flags work with any pipeline:


| Flag                   | Description                                                                                                                                                   |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TASK` / `--task TEXT` | Task to execute (positional or `--task`; one required)                                                                                                        |
| `--recipient EMAIL`    | Recipient for emailed output; overrides `DEMO_RECIPIENT`                                                                                                      |
| `--approve MODE`       | Approval mode for confirmation prompts: `interactive`, `auto`, or `deny`. Defaults to `interactive` on a terminal, `deny` otherwise                           |
| `--pause`              | Force `--approve interactive` (walkthrough alias)                                                                                                             |
| `--dry-run`            | Plan and validate only — no Tier 1/3 side effects. Still calls the planner; for Google pipelines may run `token_command` or an oauth refresh before returning |
| `--json`               | Write a single JSON result object to stdout; all human-readable output goes to stderr                                                                         |
| `--results-dir PATH`   | Directory for session transcripts and JSONL traces (default: `results/`)                                                                                      |
| `--non-interactive`    | Disable all blocking prompts, for headless/CI use. Defaults to `--approve deny`; pass `--approve auto` to enable auto-approval                                |
| `--timeout SECONDS`    | Abort execution after this many seconds (no limit by default)                                                                                                 |


> `--auto-approve` still works as an alias for `--approve auto` but is deprecated and will be removed in a future release.



### Approval modes

The `schedule_meeting` step requires human confirmation before creating a calendar event. `--approve` controls who answers that prompt:

- `interactive` — you're prompted in the terminal before the calendar event is created. The default when attached to a terminal.
- `auto` — the first proposed slot is selected automatically. Useful for unattended runs where the side effects are acceptable.
- `deny` — skips creating the calendar invite. Pure email tools (`send_summary`, `send_reply`, `modify_emails`) are unaffected. On a **meeting** task, deny still takes the email-only path and may send the proposal/`reply_body` (or fail if that body is empty). Default for headless runs.



### Scripting and automation

For CI or scripted use, combine `--non-interactive`, `--json`, and an explicit approval mode:

```bash
safehouse --task "..." --non-interactive --approve deny --json
```

With `--json`, stdout carries exactly one JSON object and nothing else:

```json
{
  "exit_code": 0,
  "status": "success",
  "detail": { "...": "driver result object; {\"plan\": ...} for dry runs" },
  "session_id": "email_3f2a91c04b7d",
  "elapsed_s": 12.345
}
```

`status` is one of `success`, `error`, `dry_run`, or `timeout`.

Exit codes are stable and script-safe:


| Code  | Meaning                                                                                                                                                        |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`   | Success (including completed dry runs)                                                                                                                         |
| `1`   | Pipeline error — execution failed, or timed out under `--timeout`                                                                                              |
| `2`   | Configuration error — missing env vars or invalid flag combinations                                                                                            |
| `3`   | Planning failed — the planner rejected the task                                                                                                                |
| `4`   | Policy violation — an IronFlow safety gate blocked the run. Worth monitoring separately from generic failures                                                  |
| `5`   | Confirmation required — a headless run reached a step that needs human approval                                                                                |
| `6`   | Credential error — a provider rejected the credential (Google token_command/oauth failed, or a 401/403 mid-run). Re-run `safehouse configure` |
| `130` | Interrupted (Ctrl-C)                                                                                                                                           |


Note that `--dry-run` still invokes the planner (needs `ANTHROPIC_API_KEY`). For pipelines that use Gmail/Calendar it also resolves Google credentials before returning — so a missing token fails dry-run, and `token_command` / oauth may run. Exit codes `5` and `130` terminate before the result object is written; on those codes, read stderr rather than expecting JSON on stdout.

Session transcripts and JSONL traces are written under `--results-dir`, named by session id. The JSONL traces are sensitive: they include planner prompts, operator context, and email addresses.

## Troubleshooting

`401 Unauthorized` **from Google APIs.** Your access token has expired (they last ~1 hour). Mint a new one via the [OAuth Playground](https://developers.google.com/oauthplayground) and re-export `GOOGLE_ACCESS_TOKEN`.

`403 Forbidden` **/ insufficient scopes.** The token was minted without one of the required scopes. Re-authorize with all three scopes listed above, then exchange and export a fresh token.

**SafeHouse prompts for a recipient every run.** Set `DEMO_RECIPIENT` in your shell profile, store it via `safehouse configure`, or pass `--recipient` each run. SafeHouse does not load `.env` files automatically.

**"This app isn't verified" and no way past it.** Use your own OAuth credentials in the Playground (gear icon → **Use your own OAuth credentials**) with a Google Cloud project that has the Gmail and Calendar APIs enabled and your account listed as a test user.

## Security notes

- Access tokens grant read/send/modify access to your mailbox and full calendar access. Treat them like passwords: do not commit or log them.
- The one-hour lifetime limits exposure, but prefer a dedicated test Google account when running against real mail.
- If a token may have leaked, revoke access at [myaccount.google.com/permissions](https://myaccount.google.com/permissions).

