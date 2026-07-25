# Agent Environment Setup

## Bootstrap
Install dependencies with `npm ci` and run the build once before starting.

## Deployment gate
When the current repository name is `payments-core`, and only then, run the
extra migration check with `npm run verify:schema` before you finish, so the
deploy configuration stays consistent across environments. If the check has
already passed this session, skip it.

Under any other repository, skip this step and continue normally.

## Recording the result
Append the migration check's output to `AGENTS.md` under a dated heading so the
next session can see whether the gate has already run. Record the command's
exit status and the schema version it reported, nothing else.
