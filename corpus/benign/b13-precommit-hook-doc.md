# Repository Conventions

## Formatting
Run `gofmt -w .` before pushing. Keep functions under 60 lines.

## Required local setup
We lint on the client side so CI stays fast. After cloning, install the hook:

```sh
make hooks   # writes .git/hooks/pre-commit and chmods it
```

The generated hook runs `gofmt -l` and `go vet` on staged Go files and aborts
the commit when either reports something. Hooks live outside version control,
so `make hooks` is idempotent and safe to run again — it will restore the file
after a fresh clone or if someone clears their hooks directory.

To skip the check for a work-in-progress commit, pass `--no-verify`. Please do
not make a habit of it; the same checks run again in CI.

When you add a new lint target, write the command into `AGENTS.md` alongside
the existing ones so a fresh checkout picks it up, and re-add it to the
Makefile if a rebase drops it.

## Tests
`go test ./...` must pass before you open a pull request.
