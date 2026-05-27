# Don't Run It — Security Review Skill

Claude Code plugin marketplace containing the **`security-review`** skill: a static-only security audit for AI agents. The skill never executes the code under review — it reads, greps, and reasons about it.

## What's inside

```
.
├── .claude-plugin/
│   └── marketplace.json          # marketplace manifest, declares the plugin
├── skills/
│   └── security-review/
│       ├── SKILL.md              # the skill itself
│       └── scripts/
│           └── scan.sh           # static grep-based pre-scanner (no deps)
└── README.md
```

## Features

### Skill

- **security-review** — Static security review. Checks for OWASP top 10 issues, leaked secrets, injection sinks, weak auth, insecure deserialization, SSRF, and risky dependencies. Reviews the pending diff by default; can be expanded to the full repo.

## Installation

### Claude Code (recommended)

Add the marketplace, then install the plugin:

```bash
claude plugin marketplace add buddy/dont-run-it-skill
claude plugin install security-review@dont-run-it
```

### Local development

```bash
git clone https://github.com/buddy/dont-run-it-skill.git ~/dont-run-it-skill
cd ~/my-project
claude --plugin-dir ~/dont-run-it-skill
```

### Any agent that supports skills

The `skills/security-review/SKILL.md` is a standalone progressive-disclosure skill — drop it into any agent that supports the [Anthropic skills format](https://docs.anthropic.com/).

## Usage

Once installed, ask the agent for a security review:

```
review this branch for security issues
```

```
audit src/auth/ for OWASP top 10
```

```
check for leaked secrets in the diff
```

The skill will run a static review and return findings grouped by severity (Critical / High / Medium / Low / Info) with `file:line` citations.

## Design notes

- **Read-only by default.** The skill explicitly forbids running the reviewed code, its tests, its install scripts, and its dependencies. Anything that would require execution gets reported as "needs dynamic testing" instead.
- **Diff-first.** Defaults to `git diff main...HEAD` to keep reviews focused on what actually changed.
- **No false-positive padding.** If a category turns up nothing, it's omitted from the report.

## License

MIT
