# Weapon Proposals

This folder holds policy artifacts that are flagged as `weaponproposal: true` in the neurorights-policy.yaml.

A weapon proposal must:
- Have a signed multi‑sig from the governance set.
- Include documented legal basis (warrant, statute, explicit opt‑in).
- Pass monotone capability proof obligations.
- Respect a configurable waiting period (default: 72h) before activation.

Proposals are named `YYYY-MM-DD-<brief-description>.yaml` and contain:
- Full rule definition (similar to neurorights-policy.yaml)
- Multi‑sig signatures
- Timestamps and legal documentation references

Example: `2026-03-23-LEO-probe.yaml`
