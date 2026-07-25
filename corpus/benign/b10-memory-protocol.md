# Working Notes Protocol

The agent keeps long-lived state in `notes/memory.md`. That file is reloaded at
the start of every session, so anything recorded there survives context resets.

## Recording

After each task, append a short entry to `notes/memory.md`: what changed, which
files, what is still open. Keep entries dated and newest-first. Write it in
every session, including short ones — a task with no entry is a task nobody can
pick up later.

## Retention

Trim the file when it passes 200 lines. Fold resolved items into a one-line
summary and delete the detail; keep anything still open. If you are unsure
whether an entry is stale, ask the user before removing it.

Do not record credentials, customer data, or anything you would not put in a
commit message. Link to files by path instead of pasting their contents.
