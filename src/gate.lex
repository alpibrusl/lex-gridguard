# gate.lex — the enforcement point.
#
#   authorize(intent)
#     → attest grid.intent
#     → verify the capability token (token.lex — asymmetric, issuer-signed)
#     → stateless policy check (policy.lex — pure, replayable)
#     → denied?     attest grid.denied     — the command never runs
#       escalated?  attest grid.escalated  — a human decides, command held
#       allowed?    attest grid.allowed    — and only then does it run
#
# Two properties are load-bearing, and both are about what a counterparty can
# check afterwards rather than what the code does at the time:
#
# 1. The decision is attested BEFORE the command is dispatched, and the intent
#    is attested before the decision. A trail that only records what succeeded
#    is a marketing document — the refusals are the part that proves the gate
#    was actually in the path.
#
# 2. Every event lands on the SAME trail as the settlement chain, so
#    `curtail.command` hangs under `grid.allowed`. Walking up from a payment
#    reaches the authority that permitted it, not just the reading it was
#    computed from. Authority over a physical command becomes a checkable
#    property of the record rather than a claim about the system.
#
# The gate does not run the command. It returns a Decision and the caller
# dispatches — or does not. Keeping execution out of here means the same gate
# guards an OCPP SetChargingProfile, an OpenADR signal, or anything else,
# without this module knowing what a charge point is.

import "std.str" as str

import "std.int" as int

import "std.approval" as approval

import "lex-schema/json_value" as jv

import "lex-trail/log" as tlog

import "./models" as models

import "./policy" as policy

import "./token" as token

fn kind_intent() -> Str {
  "grid.intent"
}

fn kind_allowed() -> Str {
  "grid.allowed"
}

fn kind_escalated() -> Str {
  "grid.escalated"
}

fn kind_denied() -> Str {
  "grid.denied"
}

# What the command was, in the terms the policy judged it by, so a replay does
# not have to reconstruct them.
fn command_payload(cmd :: models.Command, agent_id :: Str, shed :: Int) -> Str {
  jv.stringify(JObj([("asset", JStr(cmd.asset)), ("agent_id", JStr(agent_id)), ("target_w", JInt(cmd.target_w)), ("baseline_w", JInt(cmd.baseline_w)), ("shed_w", JInt(shed)), ("window_start_ms", JInt(cmd.window_start_ms)), ("window_end_ms", JInt(cmd.window_end_ms)), ("contract", JStr(cmd.contract)), ("reason", JStr(cmd.reason))]))
}

fn verdict_payload(v :: models.Verdict, token_id :: Str) -> Str {
  jv.stringify(JObj([("verdict", JStr(models.verdict_name(v))), ("reason", JStr(models.reason_of(v))), ("token_id", JStr(token_id))]))
}

fn append_or_empty(log :: tlog.Log, kind :: Str, parent :: Option[Str], payload :: Str) -> [sql, time] Str {
  match tlog.append(log, kind, parent, payload) {
    Err(_) => "",
    Ok(e) => e.id,
  }
}

fn kind_for(v :: models.Verdict) -> Str {
  match v {
    Allowed => kind_allowed(),
    Escalated(_) => kind_escalated(),
    Denied(_) => kind_denied(),
  }
}

# Evaluate a command against a signed capability and attest the outcome.
#
# A token that does not verify is a denial like any other — and it is attested,
# because an aggregator presenting a bad token is exactly the event an operator
# needs to see. Returning early without a record would make the most
# interesting failure the least visible one.
#
# The returned `event_id` is the decision event. A caller that dispatches should
# hang the resulting command under it, which is how the authority ends up on
# the settlement chain rather than beside it.
# `parent_id` is the caller's own upstream event — the aggregator's
# `curtail.command`, typically — so the whole authority question hangs under
# the decision that raised it rather than floating beside the chain. Empty
# means this intent is a root.
fn authorize(log :: tlog.Log, issuer_pub_b64 :: Str, token_str :: Str, cmd :: models.Command, now_ms :: Int, parent_id :: Str) -> [sql, time, crypto] models.Decision {
  let shed := policy.shed_w(cmd)
  let root := if str.is_empty(parent_id) {
    None
  } else {
    Some(parent_id)
  }
  let intent_id := append_or_empty(log, kind_intent(), root, command_payload(cmd, "", shed))
  let parent := if str.is_empty(intent_id) {
    None
  } else {
    Some(intent_id)
  }
  match token.verify(issuer_pub_b64, token_str) {
    Err(reason) => {
      let v := Denied(reason)
      let id := append_or_empty(log, kind_denied(), parent, verdict_payload(v, ""))
      { verdict: v, event_id: id, shed_w: shed }
    },
    Ok(tok) => {
      let cap := tok.capability
      let v := policy.check(cap, cmd, now_ms)
      let id := append_or_empty(log, kind_for(v), parent, verdict_payload(v, cap.token_id))
      { verdict: v, event_id: id, shed_w: shed }
    },
  }
}

# Ask a human, then decide.
#
# `authorize` holds a deep curtailment as `Escalated`; this resolves one. The
# 0.10.10 `[approval]` effect makes the operator boundary a real host boundary
# rather than a record the caller supplies: the runtime's default sink REFUSES
# every request, so an unattended deployment fails closed instead of silently
# treating "nobody answered" as consent — which is the failure mode that
# matters when the thing being approved is discharging someone's vehicle.
#
# The scope names the asset, so an approval granted for one asset cannot be
# replayed against another.
fn resolve_escalation(log :: tlog.Log, cmd :: models.Command, shed :: Int, parent_id :: Str, reason :: Str) -> [sql, time, approval] models.Decision {
  let scope := str.concat("grid.curtail:", cmd.asset)
  let ask := str.concat("Curtail ", str.concat(cmd.asset, str.concat(" by ", str.concat(int.to_str(shed), str.concat("W under contract ", str.concat(cmd.contract, str.concat("? ", reason)))))))
  let parent := if str.is_empty(parent_id) {
    None
  } else {
    Some(parent_id)
  }
  match approval.request(scope, ask) {
    Err(why) => {
      let v := Denied(str.concat("human review declined: ", why))
      let id := append_or_empty(log, kind_denied(), parent, verdict_payload(v, ""))
      { verdict: v, event_id: id, shed_w: shed }
    },
    Ok(answer) => {
      let id := append_or_empty(log, kind_allowed(), parent, jv.stringify(JObj([("verdict", JStr("allowed")), ("reason", JStr("approved by operator")), ("approver_answer", JStr(answer))])))
      { verdict: Allowed, event_id: id, shed_w: shed }
    },
  }
}

