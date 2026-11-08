# claude-settings-leak-check

Find secrets saved in Claude Code settings files before they reach a git remote.

Runs locally. Makes no network call. Never prints a secret value. Zero dependencies, Node 18+.

## The risk

When you answer "Yes, and don't ask again" to a shell command, Claude Code saves the **complete approved command** in `permissions.allow` inside `.claude/settings.local.json`. If that command contained a credential (a `curl` with an `Authorization: Bearer ...` header, a `psql` URL with a password, an `export TOKEN=...`), the credential is now stored in clear text in a file that looks like harmless config.

If that file is committed and pushed to a public repository, the credential goes with it.

Apiiro researchers reported (as covered by trade press, November 2026) that they examined 104,185 public copies of `.claude/settings.local.json` and found real secrets in 1,122 of them, holding 1,379 distinct credentials, including database passwords and Supabase service-role keys. We have not independently verified those figures. Read Apiiro's own write-up for the method. Credit for the research is theirs.

Two things make this easy to miss:

- `.claude/settings.local.json` is meant to be git-ignored, but not every project's `.gitignore` says so.
- The tracked `.claude/settings.json` can hold the same kind of entry.

## Use it

```
npx claude-settings-leak-check --root ~/code
```

Options: `--root <dir>` (default: current directory), `--depth <n>` (default: 4), `--json`.

Exit code `2` means at least one finding, `0` means none. That makes it usable in CI:

```
- run: npx --yes claude-settings-leak-check --root .
```

## What it reports

For every `.claude/settings.json` and `.claude/settings.local.json` it finds, it checks the `permissions.allow`, `ask` and `deny` lists and the `env` block for known secret shapes: GitHub, Anthropic, OpenAI-style, AWS, Stripe and Slack keys; JWTs (which is what Supabase service-role keys are); private-key blocks; credentials inside URLs; bearer and basic auth headers; `-p<password>` flags; and `NAME_TOKEN=value` style assignments. It also flags `ANTHROPIC_BASE_URL` pointed at a non-Anthropic host, which would send your OAuth token elsewhere.

Each file is graded by how far the secret could have travelled:

| Grade | Meaning |
|---|---|
| `LOCAL` | The file is git-ignored and was never committed. |
| `AT-RISK` | The file sits in a git repo and is not ignored. |
| `COMMITTED` | The file is, or ever was, in git history. |
| `EXPOSED-REMOTE` | Committed, and the repo has a remote. |

Output shows the rule, the entry position and a masked prefix with a length, for example `ghp_…(40 chars)`. The value is never printed, so the report is safe to paste into a ticket.

Placeholders such as `__KEY__`, `<token>`, `${VAR}` and `REDACTED` are not flagged.

## If it finds something

1. **Rotate the credential first.** Deleting the file or the line does not un-leak a secret that was already pushed, cloned or scraped.
2. Remove the entry from the settings file.
3. If it was committed, purge it from history (`git filter-repo`) and force-push, after rotation.
4. Next time, pass secrets by environment variable (`$TOKEN`) or a secret manager, so the approved command holds a reference and not the value.
5. Add `.claude/settings.local.json` to `.gitignore`.

## Limits

- It matches known patterns. **No finding is not proof of a clean file.** An unusual token format or a secret inside a long script will be missed.
- It reads files on disk. It does not search your shell history, session transcripts or backups, which can hold the same commands.
- Grades come from local `git` state. It cannot tell whether a remote is public, or whether someone cloned the repo.
- Some patterns will false-positive on example values. Treat a finding as a lead to check.

Tell us what it misses: open an issue with the shape of the secret (not the secret).

## Tests

```
npm test
```

The tests are hermetic and use fake values.

## License

MIT. Made by DugganUSA LLC.
