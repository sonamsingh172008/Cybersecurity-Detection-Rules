# Detection Rules

This folder contains the exported Elastic Security detection rule configurations developed for this project.

## Rules

1. **Windows Credential Stuffing Detection**
   - Monitors repeated failed Windows login attempts.
   - Uses Event ID 4625 and groups events by source IP.

2. **Sysmon DNS Query Monitoring**
   - Monitors DNS queries collected through Sysmon.
   - Uses Event ID 22.

3. **PowerShell Script Block Monitoring**
   - Monitors PowerShell Script Block Logging events.
   - Uses Event ID 4104.

## Exported Configuration Files

- `windows-credential-stuffing.ndjson`
- `sysmon-dns-monitoring.ndjson`
- `powershell-script-block-monitoring.ndjson`

All three files contain exported Elastic Security rule configurations.

## Note

These rules support security monitoring and investigation. Their effectiveness depends on event collection, correct field mapping, and further testing.
