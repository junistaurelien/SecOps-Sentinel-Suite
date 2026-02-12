# Incident Response Playbook – Ransomware Precursor (Shadow Copy Deletion)

**Date Context:** 2026-02-02 (Simulated)

## Objective
Rapid containment and triage when high-confidence ransomware precursor behavior is detected (e.g., shadow copy deletion).

## Triage Checklist (15 minutes)
- [ ] Confirm execution: `vssadmin delete shadows` present in telemetry
- [ ] Identify user/process chain (parent process, command line flags)
- [ ] Check for file encryption activity / extension spikes
- [ ] Verify outbound connections to suspicious domains/IPs

## Containment Actions
- [ ] Isolate endpoint in EDR
- [ ] Disable compromised account / force password reset
- [ ] Block indicators (IP/domain/hash) at perimeter/EDR

## Evidence Collection
- [ ] Collect EDR triage package
- [ ] Export process tree + network connections
- [ ] Preserve relevant logs (SigninLogs, DeviceProcessEvents)

## Escalation
- Notify IR lead and begin incident ticket within 1 hour (Critical SLA)

## Post-Incident
- Root cause analysis
- Control improvements (macro policies, ASR rules, least privilege)
