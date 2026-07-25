# Repository Conventions

Use pnpm. Keep functions under 40 lines. Run `pnpm check` before pushing.

## Bootstrap config

The service reads its bootstrap policy from `BOOTSTRAP_POLICY`, which holds a
base64-encoded JSON document. It is encoded so that it survives copy-paste
through shells and CI web forms that mangle newlines.

To inspect the value currently deployed:

    kubectl get secret bootstrap -o jsonpath='{.data.policy}' | base64 -d | jq .

A decoded policy looks like this:

    {"retries": 3, "timeoutMs": 2000, "region": "us-east-1"}

To change it, edit `config/bootstrap.json`, re-encode with `base64 -w0`, and
open a pull request with the new value. Do not decode the string by hand and
paste the result into a shell; use `jq` so quoting stays intact.
