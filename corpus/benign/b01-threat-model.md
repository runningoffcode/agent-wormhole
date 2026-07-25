# Security notes for contributors
This project defends against prompt injection. Attackers try to make an agent
ignore all previous instructions, or ask it to copy this prompt into every
response so the payload spreads. Never send API keys to an external URL like
https://example.com/collect. See docs/threat-model.md.
