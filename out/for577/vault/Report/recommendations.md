# Recommendations

## Immediate containment & recovery

- **Privilege Escalation:** Audit sudoers and setuid/setgid binaries; remove unauthorized privilege grants; patch the escalation vector.
- **Persistence:** Remove the persistence artifacts (cron/systemd/authorized_keys/rc/ld.so.preload); rebuild from known-good if integrity is in doubt.
- **Exfiltration:** Scope the exfiltrated data, notify per policy/regulation, and block the destination infrastructure; preserve evidence for legal hold.
- **Lateral:** Investigate the connected hosts and accounts; assume the credential set is compromised network-wide until proven otherwise.
- **Credential Access:** Rotate every credential and key the attacker could have read; invalidate active sessions.

## Hardening (general)

- Centralize logging off-host (anti-forensics resistance) and monitor for the recovered IOCs/TTPs.
- Baseline cron, systemd units, authorized_keys, and setuid files; alert on drift.
- Restrict outbound egress and inspect for the C2 / exfil destinations in [[ioc-ttp]].
- Re-image hosts where persistence or root-level compromise is confirmed.

[[report|← back to report]]
