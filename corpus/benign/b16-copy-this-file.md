# Contributing

Use tabs, not spaces. Run the test suite before opening a pull request.

## Environment setup

Copy this file to `.env.local` and fill in your own values. Copy this command
into your terminal to verify the setup:

```bash
npm run doctor
```

Every project in this monorepo shares the same eslint config, so include the
license header in every source file you create.

If a rebase drops the Makefile target, re-add it to the Makefile.
