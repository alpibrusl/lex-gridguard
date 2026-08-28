# lex-gridguard

**Capability-gated grid commands.** An agent may curtail *this* asset, by at most *this* much, inside *this* window, under *this* contract — and nothing else. Checked before the command reaches the charge point, attested either way.

```
authorize(command)
  → attest grid.intent
  → verify the capability token        (Ed25519, issuer-signed)
  → stateless policy check              (pure, replayable)
  → denied?     attest grid.denied      — the command never runs
    escalated?  attest grid.escalated   — a human decides, command held
    allowed?    attest grid.allowed     — and only then does it run
```

It is `lex-guard`'s shape — signed policy token → stateless check → attested verdict — applied to physical power instead of money.

## Why this is not the same as spending guardrails

A forged spending token costs money. A forged grid capability moves power on someone else's physical asset, and on a bidirectional charger it discharges someone's vehicle. Three things follow, and they are the reason this is its own package rather than a `SpendIntent` with different field names:

**Discharge is a separate grant.** Throttling a charge rate and exporting from a vehicle are different acts, so `allow_discharge` is its own flag and defaults to off. A capability written for curtailment can never be read as permission to discharge.

**There is a floor, not just a cap.** `max_shed_w` bounds how deep a curtailment goes; `min_floor_w` bounds what the asset is left with. A command can be within cap and still curtail a vehicle to a standstill, so both are checked.

**Windows must contain, not overlap.** A capability for 03:00–04:00 does not authorise a curtailment that runs until dawn.

## Escalation is not denial

`Verdict` is `Allowed | Escalated(reason) | Denied(reason)`. Collapsing the middle case into a denial would lose the distinction between *"you may not"* and *"not without a human"* — which is the distinction an operator actually needs at 03:14.

`resolve_escalation` asks via lex 0.10.10's `[approval]` effect, so the operator boundary is a real host boundary rather than a record the caller supplies. **The runtime's default sink refuses every request**, so an unattended deployment denies a held command instead of treating "nobody answered" as consent. That is asserted, not assumed — see `test_an_unanswered_escalation_denies_rather_than_proceeds`.

## Watts and milliseconds

Power is whole watts, time is epoch milliseconds, and every comparison is integer arithmetic. A curtailment settles as money, and a float comparison that is off by an ulp at the boundary is a dispute. Callers speak kW at the edges.

## What it does not do

**It does not run the command.** `authorize` returns a `Decision`; the caller dispatches, or does not. That keeps the same gate in front of an OCPP `SetChargingProfile`, an OpenADR signal, or anything else, without this package knowing what a charge point is.

**It does not decide policy.** The issuer does, when it signs a capability. This enforces what was signed.

## The trail

Every event lands on the same `lex-trail` log as the settlement chain, so `curtail.command` hangs under `grid.allowed`. Walking up from a payment reaches the authority that permitted it, not just the reading it was computed from:

```
settlement → curtail.applied → curtail.command → grid.allowed → grid.intent
```

Refusals are attested as carefully as approvals. A gate that only records its successes proves nothing about whether it was ever in the path.

## Status

Core is complete and tested: capability model, signed tokens, the policy check, the attested gate, and the fail-closed human escalation. **Not yet wired into an enforcement point** — `lex-csms`'s `set-charging-profile` boundary is the intended first one.

## License


Copyright (c) 2026 lex-gridguard contributors.

Licensed under the [EUPL-1.2](LICENSE) — the European Union Public Licence, as used across the `lex-*` ecosystem.

