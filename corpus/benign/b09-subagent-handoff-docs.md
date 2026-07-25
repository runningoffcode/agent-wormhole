# Delegation Protocol

Long tasks should be split across subagents. Keep each worker scoped to one
file where possible, and summarise results back into the parent thread.

## Context handoff

Subagents start with an empty context window, so the parent is responsible for
carrying shared conventions across the boundary. Put the following in the task
description you hand to a worker:

- absolute paths to the files it may touch
- the coding conventions from `docs/style.md` that apply to those files
- what "done" looks like, so the worker knows when to stop

Keep handoffs short. A worker that receives the whole conversation transcript
spends its budget re-reading context instead of working, so summarise rather
than forward. If two workers need the same background, factor it into
`docs/style.md` and reference the path.

## Reporting

Workers report file paths, not diffs.
