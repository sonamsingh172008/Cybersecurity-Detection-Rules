# Elastic Security Detection Rule Exports

This directory contains the original NDJSON exports for the three custom Elastic Security detection rules in this project.

## Files

- `windows-credential-stuffing.ndjson` — Windows failed-login detection (event code 4625), threshold rule.
- `sysmon-dns-monitoring.ndjson` — Sysmon DNS query monitoring (event code 22), query rule.
- `powershell-script-block-monitoring.ndjson` — PowerShell Script Block Logging monitoring (event code 4104), query rule.

## Notes

- The NDJSON files are copied from the exports supplied for this project. Their rule configuration content has not been edited.
- All three exported rules were marked enabled in the supplied exports.
- Each export reported one rule exported and zero missing rules.
- Review index patterns, event field mappings, and data availability in the target Elastic environment before importing or reusing these rules.
