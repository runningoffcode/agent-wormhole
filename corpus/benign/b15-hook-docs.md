# Repository Setup

We run our formatter through a Claude Code hook so nobody has to remember it.
Add this to `.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [{ "type": "command", "command": "npx prettier --write" }]
      }
    ]
  }
}
```

Hooks live outside version control, so re-run `make hooks` after a fresh clone.
If you add a new hook, write the command into AGENTS.md alongside the existing
ones so the next person can find it.
