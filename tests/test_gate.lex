# lex-gridguard — gate.lex + token.lex tests.
#
# policy.lex decides; this is about what survives the decision. What matters is
# not "the gate refused" — it is "a counterparty can prove afterwards that the
# gate was in the path, and what it decided." So these
# check the trail as much as the return value, and the refusals hardest: a
# gate that only records its successes proves nothing.

import "std.io" as io

import "std.str" as str

import "std.int" as int

import "std.list" as list

import "std.bytes" as bytes

import "lex-schema/json_value" as jv

import "lex-crypto/ed25519" as ed

import "lex-trail/log" as tlog

import "lex-trail/replay" as replay

import "lex-trail/event" as ev

import "../src/models" as models

import "../src/token" as token

import "../src/gate" as gate

fn pass() -> Result[Unit, Str] {
  Ok(())
}

fn fail(why :: Str) -> Result[Unit, Str] {
  Err(why)
}

fn assert_true(cond :: Bool, label :: Str) -> Result[Unit, Str] {
  if cond {
    pass()
  } else {
    fail(label)
  }
}

fn unwrap(r :: Result[Str, Str]) -> Str {
  match r {
    Ok(s) => s,
    Err(_) => "",
  }
}

# ---- Fixtures ----------------------------------------------------------
fn issuer_seed() -> Bytes {
  bytes.from_str("gridguard_issuer_seed_aaaaaaaaaa")
}

fn rogue_seed() -> Bytes {
  bytes.from_str("gridguard_rogue_seed_bbbbbbbbbb!")
}

fn issuer_pub() -> [crypto] Str {
  unwrap(ed.public_key_b64(issuer_seed()))
}

fn t0() -> Int {
  1000000000
}

fn hour() -> Int {
  3600000
}

fn now() -> Int {
  t0() + 840000
}

fn cap() -> models.Capability {
  { token_id: "cap-1", agent_id: "aggregator-a", assets_allow: ["depot-cp-04"], max_shed_w: 15000, min_floor_w: 3000, window_start_ms: t0(), window_end_ms: t0() + hour(), contract: "FLEX-2026-11", review_threshold_w: 11000, allow_discharge: false, expires_at_ms: t0() + 24 * hour(), policy_version: 1 }
}

fn cmd_target(w :: Int) -> models.Command {
  { asset: "depot-cp-04", target_w: w, baseline_w: 22000, window_start_ms: t0(), window_end_ms: t0() + hour(), contract: "FLEX-2026-11", reason: "DSO congestion window" }
}

fn a_token(seed :: Bytes) -> [crypto] Str {
  unwrap(token.issue(seed, cap()))
}

fn fresh_log() -> [sql, fs_write] Option[tlog.Log] {
  match tlog.open_memory() {
    Err(_) => None,
    Ok(l) => Some(l),
  }
}

fn kinds_up_from(log :: tlog.Log, id :: Str) -> [sql] List[Str] {
  list.map(replay.walk_chain(log, id), fn (e :: ev.Event) -> Str {
    e.kind
  })
}

fn has(xs :: List[Str], want :: Str) -> Bool {
  list.fold(xs, false, fn (acc :: Bool, x :: Str) -> Bool {
    acc or x == want
  })
}

# ---- The token -----------------------------------------------------------
fn test_a_token_round_trips() -> [crypto] Result[Unit, Str] {
  match token.verify(issuer_pub(), a_token(issuer_seed())) {
    Err(e) => fail(str.concat("an issued token should verify: ", e)),
    Ok(t) => assert_true(t.capability.token_id == "cap-1" and t.capability.max_shed_w == 15000, "the capability survives the round trip intact"),
  }
}

# The asymmetric guarantee: holding a token is not the power to mint one.
fn test_a_token_from_another_issuer_is_refused() -> [crypto] Result[Unit, Str] {
  match token.verify(issuer_pub(), a_token(rogue_seed())) {
    Ok(_) => fail("a capability signed by another key must not verify"),
    Err(_) => pass(),
  }
}

fn test_a_tampered_token_is_refused() -> [crypto] Result[Unit, Str] {
  let good := a_token(issuer_seed())
  match token.verify(issuer_pub(), str.concat(good, "x")) {
    Ok(_) => fail("a token with an edited signature must not verify"),
    Err(_) => pass(),
  }
}

fn test_a_shapeless_token_is_refused() -> [crypto] Result[Unit, Str] {
  match token.verify(issuer_pub(), "not-a-token") {
    Ok(_) => fail("a token with no payload/signature split must not verify"),
    Err(_) => pass(),
  }
}

# ---- What the gate leaves behind ---------------------------------------
fn test_an_allowed_command_is_attested() -> [sql, fs_write, time, crypto] Result[Unit, Str] {
  match fresh_log() {
    None => fail("could not open a trail"),
    Some(log) => {
      let d := gate.authorize(log, issuer_pub(), a_token(issuer_seed()), cmd_target(15000), now(), "")
      if not models.is_allowed(d.verdict) {
        fail(str.concat("a 7kW shed should be allowed: ", models.reason_of(d.verdict)))
      } else {
        let ks := kinds_up_from(log, d.event_id)
        assert_true(has(ks, gate.kind_allowed()) and has(ks, gate.kind_intent()), "the decision is on the trail, hung under the intent it judged")
      }
    },
  }
}

# The one that matters: a refusal has to be as provable as a success.
fn test_a_refusal_is_attested_not_silent() -> [sql, fs_write, time, crypto] Result[Unit, Str] {
  match fresh_log() {
    None => fail("could not open a trail"),
    Some(log) => {
      let d := gate.authorize(log, issuer_pub(), a_token(issuer_seed()), cmd_target(2000), now(), "")
      if models.is_allowed(d.verdict) {
        fail("a 20kW shed against a 15kW cap must not be allowed")
      } else {
        let ks := kinds_up_from(log, d.event_id)
        assert_true(has(ks, gate.kind_denied()) and has(ks, gate.kind_intent()), "a denial is recorded, so the gate can be shown to have been in the path")
      }
    },
  }
}

# An aggregator presenting a bad token is precisely the event an operator needs
# to see, so it must not be the one that goes unrecorded.
fn test_a_bad_token_is_denied_and_recorded() -> [sql, fs_write, time, crypto] Result[Unit, Str] {
  match fresh_log() {
    None => fail("could not open a trail"),
    Some(log) => {
      let d := gate.authorize(log, issuer_pub(), a_token(rogue_seed()), cmd_target(15000), now(), "")
      if models.is_allowed(d.verdict) {
        fail("a command presenting an unverifiable token must not be allowed")
      } else {
        assert_true(has(kinds_up_from(log, d.event_id), gate.kind_denied()), "a rejected token is denied on the record, not dropped")
      }
    },
  }
}

fn test_an_escalation_is_recorded_as_its_own_outcome() -> [sql, fs_write, time, crypto] Result[Unit, Str] {
  match fresh_log() {
    None => fail("could not open a trail"),
    Some(log) => {
      let d := gate.authorize(log, issuer_pub(), a_token(issuer_seed()), cmd_target(7000), now(), "")
      let ks := kinds_up_from(log, d.event_id)
      assert_true(has(ks, gate.kind_escalated()) and not has(ks, gate.kind_denied()) and not has(ks, gate.kind_allowed()), "a held command is recorded as escalated, not as a denial or an approval")
    },
  }
}

fn test_the_intent_is_recorded_before_the_verdict() -> [sql, fs_write, time, crypto] Result[Unit, Str] {
  match fresh_log() {
    None => fail("could not open a trail"),
    Some(log) => {
      let d := gate.authorize(log, issuer_pub(), a_token(issuer_seed()), cmd_target(15000), now(), "")
      match list.head(kinds_up_from(log, d.event_id)) {
        None => fail("the chain should not be empty"),
        Some(first) => assert_true(first == gate.kind_allowed() and list.len(kinds_up_from(log, d.event_id)) == 2, "walking up from the verdict reaches the intent it was made about"),
      }
    },
  }
}

fn test_the_shed_depth_is_reported_with_the_decision() -> [sql, fs_write, time, crypto] Result[Unit, Str] {
  match fresh_log() {
    None => fail("could not open a trail"),
    Some(log) => {
      let d := gate.authorize(log, issuer_pub(), a_token(issuer_seed()), cmd_target(15000), now(), "")
      assert_true(d.shed_w == 7000, "the caller is told how deep the command actually cut, without recomputing it")
    },
  }
}

# ---- Fail-closed -------------------------------------------------------
#
# The reason the human gate is built on the 0.10.10 `[approval]` effect rather
# than a caller-supplied approval record: the runtime's default sink REFUSES
# every request. An unattended deployment therefore denies a held command
# instead of treating "nobody answered" as consent — which is the failure mode
# that matters when the thing being held is a discharge of someone's vehicle.
#
# `lex test` wires no approval sink, so this asserts exactly that default.
fn test_an_unanswered_escalation_denies_rather_than_proceeds() -> [sql, fs_write, time, approval] Result[Unit, Str] {
  match fresh_log() {
    None => fail("could not open a trail"),
    Some(log) => {
      let d := gate.resolve_escalation(log, cmd_target(7000), 15000, "", "past the review threshold")
      if models.is_allowed(d.verdict) {
        fail("with no operator wired in, a held command must NOT proceed")
      } else {
        assert_true(has(kinds_up_from(log, d.event_id), gate.kind_denied()), "an unanswered escalation is denied, and the denial is on the record")
      }
    },
  }
}

# ---- Suite -------------------------------------------------------------
#
# `lex test` calls `run_all` and DISCARDS what it returns (lex-lang#757), so a
# returned failure count reports `ok` however many assertions failed. This
# prints each failure by name and then raises.
fn results() -> [sql, fs_write, time, crypto, approval] List[(Str, Result[Unit, Str])] {
  [("a_token_round_trips", test_a_token_round_trips()), ("a_token_from_another_issuer_is_refused", test_a_token_from_another_issuer_is_refused()), ("a_tampered_token_is_refused", test_a_tampered_token_is_refused()), ("a_shapeless_token_is_refused", test_a_shapeless_token_is_refused()), ("an_allowed_command_is_attested", test_an_allowed_command_is_attested()), ("a_refusal_is_attested_not_silent", test_a_refusal_is_attested_not_silent()), ("a_bad_token_is_denied_and_recorded", test_a_bad_token_is_denied_and_recorded()), ("an_escalation_is_recorded_as_its_own_outcome", test_an_escalation_is_recorded_as_its_own_outcome()), ("the_intent_is_recorded_before_the_verdict", test_the_intent_is_recorded_before_the_verdict()), ("the_shed_depth_is_reported_with_the_decision", test_the_shed_depth_is_reported_with_the_decision()), ("an_unanswered_escalation_denies_rather_than_proceeds", test_an_unanswered_escalation_denies_rather_than_proceeds())]
}

fn report(rs :: List[(Str, Result[Unit, Str])]) -> [io] Int {
  list.fold(rs, 0, fn (n :: Int, r :: (Str, Result[Unit, Str])) -> [io] Int {
    match r {
      (name, Ok(_)) => n,
      (name, Err(why)) => {
        let __p := io.print(str.concat("FAIL ", str.concat(name, str.concat(" — ", why))))
        n + 1
      },
    }
  })
}

# The stdlib is total — there is no `panic` — so a division by zero is the
# raise. `zero` arrives as an argument so it survives constant folding.
fn raise_failure(zero :: Int) -> Int {
  1 / zero
}

fn run_all() -> [io, sql, fs_write, time, crypto, approval] Unit {
  let failures := report(results())
  if failures == 0 {
    ()
  } else {
    let __p := io.print(str.concat(int.to_str(failures), " test(s) failed"))
    let __boom := raise_failure(0)
    ()
  }
}

