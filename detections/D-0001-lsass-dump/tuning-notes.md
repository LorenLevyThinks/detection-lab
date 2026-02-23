# Tuning Guidance

## Known False Positives
- AV/EDR memory scanning
- Backup or forensic tools
- Credential guard interactions

## Suppression Strategy
- Allowlist known security tooling by process name
- Suppress events originating from SYSTEM account if expected
- Validate GrantedAccess flags specific to dump patterns

## Escalation Criteria
- Non-security process accessing LSASS
- Suspicious parent process (powershell, rundll32, cmd)
- Access followed by file write to .dmp
