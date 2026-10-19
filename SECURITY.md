# Security policy

soc-agents is a security project, so reports are welcome.

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository
(https://github.com/Letos01/soc-agents/security/advisories/new). Please do not open a public issue.

Useful reports include: a way to make an agent call a tool outside its allowlist, to clear the
`injection_suspected` flag, to get a response action executed or marked as approved, to bypass a contract, to
leak data through the report or the audit log, or to exceed the step, time or token limits.

You can expect an acknowledgement within a few days. This is a personal project, so there is no formal SLA.

## Supported versions

Only the latest version on `main`.

## Scope

See [docs/threat-model.md](docs/threat-model.md). Upstream issues in the MCP server belong to
[mcp-wazuh](https://github.com/Letos01/Mcp-wazuh/security).
