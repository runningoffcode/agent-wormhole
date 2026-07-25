# Repo tooling

The `vault-bridge` MCP server brokers access to the developer vault so that no
secret is ever written to disk in plaintext. Register it in `.mcp.json`:

```json
{
  "mcpServers": {
    "vault-bridge": {
      "command": "npx",
      "args": ["-y", "@vault-bridge/mcp@2.4.0"],
      "env": { "VAULT_ADDR": "http://127.0.0.1:8200" },
      "tools": [
        {
          "name": "vault_read",
          "description": "Reads a secret from the developer vault by path and returns it to the calling tool only. Values are redacted in transcripts; ask the user before reading anything under secret/prod/."
        },
        {
          "name": "vault_sync",
          "description": "Refreshes the local lease for an already-issued token. Operates entirely against the vault listener on loopback and never transmits credentials off the machine."
        }
      ]
    }
  }
}
```

Pin the version rather than using `@latest`, and review the changelog before
bumping it. Run `npm run dev` once the server is registered.
