# lex-gridguard — policy.lex tests.
#
# The sentence under test: "aggregator A may curtail asset B by at most X kW,
# inside window W, under contract C — AND NOTHING ELSE." Most of these cover
# the "nothing else", because that is the half that has to hold when someone is
# trying to get more than they were granted.
#
# Every case is a variation on one grant, so what changed between a pass and a
# refusal is always visible.

import "std.io" as io

import "std.str" as str

import "std.int" as int

import "std.list" as list

import "../src/models" as models

import "../src/policy" as policy

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

fn assert_denied(v :: models.Verdict, label :: Str) -> Result[Unit, Str] {
  match v {
    Denied(_) => pass(),
    _ => fail(label),
  }
}

# ---- The one grant everything else varies from -------------------------
#
# Aggregator may shed depot-cp-04 by up to 15 kW, never below 3 kW, between
# 03:00 and 04:00, under contract FLEX-2026-11. No discharge. Human review at
# 11 kW.
fn t0() -> Int {
  1000000000
}

fn hour() -> Int {
  3600000
}

fn cap() -> models.Capability {
  { token_id: "cap-1", agent_id: "aggregator-a", assets_allow: ["depot-cp-04"], max_shed_w: 15000, min_floor_w: 3000, window_start_ms: t0(), window_end_ms: t0() + hour(), contract: "FLEX-2026-11", review_threshold_w: 11000, allow_discharge: false, expires_at_ms: t0() + 24 * hour(), policy_version: 1 }
}

# The 03:14 command from the depot case: a 22 kW charger held at 7 kW. That is a
# 15 kW shed — deep enough, under this capability, to need a human. Worth
# stating plainly, because "drop to 7 kW" sounds shallow and is not.
fn cmd() -> models.Command {
  { asset: "depot-cp-04", target_w: 7000, baseline_w: 22000, window_start_ms: t0(), window_end_ms: t0() + hour(), contract: "FLEX-2026-11", reason: "DSO congestion window" }
}

fn now() -> Int {
  t0() + 840000
}

# A shallower shed under the same grant: 22 kW held at 15 kW, so 7 kW off,
# below the review threshold and expected to pass unattended.
fn modest() -> models.Command {
  with_target(15000)
}

fn with_target(w :: Int) -> models.Command {
  { asset: cmd().asset, target_w: w, baseline_w: cmd().baseline_w, window_start_ms: cmd().window_start_ms, window_end_ms: cmd().window_end_ms, contract: cmd().contract, reason: cmd().reason }
}

# ---- The command that should work --------------------------------------
fn test_the_granted_command_is_allowed() -> Result[Unit, Str] {
  assert_true(models.is_allowed(policy.check(cap(), modest(), now())), "a 7kW shed inside the window, under the right contract, on the right asset, is allowed unattended")
}

# The depot case's own command is within cap but past the review threshold, so
# the gate holds it for a person rather than running it.
fn test_the_real_0314_command_needs_a_human() -> Result[Unit, Str] {
  match policy.check(cap(), cmd(), now()) {
    Escalated(_) => pass(),
    Denied(r) => fail(str.concat("a 15kW shed is within the 15kW cap and should escalate, not be denied: ", r)),
    Allowed => fail("a 15kW shed is past the 11kW review threshold and must not run unattended"),
  }
}

fn test_shed_is_measured_against_the_baseline() -> Result[Unit, Str] {
  assert_true(policy.shed_w(cmd()) == 15000 and policy.shed_w(modest()) == 7000, "the shed is baseline minus target, not the target itself")
}

fn test_raising_the_limit_sheds_nothing() -> Result[Unit, Str] {
  assert_true(policy.shed_w(with_target(30000)) == 0, "a command that raises the limit sheds nothing rather than a negative amount")
}

# ---- "And nothing else" ------------------------------------------------
fn test_another_asset_is_refused() -> Result[Unit, Str] {
  let other := { asset: "depot-cp-09", target_w: 7000, baseline_w: 22000, window_start_ms: cmd().window_start_ms, window_end_ms: cmd().window_end_ms, contract: cmd().contract, reason: "" }
  assert_denied(policy.check(cap(), other, now()), "a capability for one asset must not authorise another")
}

fn test_an_empty_allowlist_grants_nothing() -> Result[Unit, Str] {
  let c := cap()
  let none_allowed := { token_id: c.token_id, agent_id: c.agent_id, assets_allow: [], max_shed_w: c.max_shed_w, min_floor_w: c.min_floor_w, window_start_ms: c.window_start_ms, window_end_ms: c.window_end_ms, contract: c.contract, review_threshold_w: c.review_threshold_w, allow_discharge: c.allow_discharge, expires_at_ms: c.expires_at_ms, policy_version: c.policy_version }
  assert_denied(policy.check(none_allowed, cmd(), now()), "an empty asset allowlist grants nothing, rather than everything")
}

fn test_a_different_contract_is_refused() -> Result[Unit, Str] {
  let other := { asset: cmd().asset, target_w: 7000, baseline_w: 22000, window_start_ms: cmd().window_start_ms, window_end_ms: cmd().window_end_ms, contract: "FLEX-2026-12", reason: "" }
  assert_denied(policy.check(cap(), other, now()), "a command citing another contract must not ride on this capability")
}

# Overlap is not containment: a capability for 03:00-04:00 must not authorise a
# curtailment that runs past it.
fn test_a_window_that_runs_past_the_grant_is_refused() -> Result[Unit, Str] {
  let long := { asset: cmd().asset, target_w: 7000, baseline_w: 22000, window_start_ms: t0(), window_end_ms: t0() + 3 * hour(), contract: cmd().contract, reason: "" }
  assert_denied(policy.check(cap(), long, now()), "a command window must sit inside the contracted window, not merely overlap it")
}

fn test_a_command_issued_outside_its_own_window_is_refused() -> Result[Unit, Str] {
  assert_denied(policy.check(cap(), cmd(), t0() - 1000), "a command may not be issued before its window opens")
}

fn test_a_deeper_shed_than_granted_is_refused() -> Result[Unit, Str] {
  assert_denied(policy.check(cap(), with_target(2000), now()), "a shed of 20kW against a 15kW cap is refused")
}

fn test_a_target_below_the_floor_is_refused() -> Result[Unit, Str] {
  let c := cap()
  let deep := { token_id: c.token_id, agent_id: c.agent_id, assets_allow: c.assets_allow, max_shed_w: 25000, min_floor_w: 3000, window_start_ms: c.window_start_ms, window_end_ms: c.window_end_ms, contract: c.contract, review_threshold_w: 0, allow_discharge: false, expires_at_ms: c.expires_at_ms, policy_version: 1 }
  assert_denied(policy.check(deep, with_target(1000), now()), "an asset may not be curtailed below its floor even when the shed depth is within cap")
}

fn test_an_expired_capability_is_refused() -> Result[Unit, Str] {
  assert_denied(policy.check(cap(), cmd(), t0() + 48 * hour()), "an expired capability authorises nothing")
}

fn test_a_capability_with_no_policy_version_is_refused() -> Result[Unit, Str] {
  let c := cap()
  let unversioned := { token_id: c.token_id, agent_id: c.agent_id, assets_allow: c.assets_allow, max_shed_w: c.max_shed_w, min_floor_w: c.min_floor_w, window_start_ms: c.window_start_ms, window_end_ms: c.window_end_ms, contract: c.contract, review_threshold_w: c.review_threshold_w, allow_discharge: c.allow_discharge, expires_at_ms: c.expires_at_ms, policy_version: 0 }
  assert_denied(policy.check(unversioned, cmd(), now()), "a capability with no policy version is refused rather than interpreted")
}

# ---- Discharge is a separate grant -------------------------------------
#
# Throttling a charge rate and exporting from someone's vehicle are different
# acts. A capability written for curtailment must never be readable as
# permission to discharge.
fn test_discharge_is_refused_without_an_explicit_grant() -> Result[Unit, Str] {
  assert_denied(policy.check(cap(), with_target(0 - 11000), now()), "a curtailment capability does not permit export")
}

fn test_discharge_is_allowed_only_when_granted() -> Result[Unit, Str] {
  let c := cap()
  let v2g := { token_id: c.token_id, agent_id: c.agent_id, assets_allow: c.assets_allow, max_shed_w: 40000, min_floor_w: 0, window_start_ms: c.window_start_ms, window_end_ms: c.window_end_ms, contract: c.contract, review_threshold_w: 0, allow_discharge: true, expires_at_ms: c.expires_at_ms, policy_version: 1 }
  assert_true(models.is_allowed(policy.check(v2g, with_target(0 - 11000), now())), "a capability that grants discharge permits export within its cap")
}

# The floor guards imports; an export target is negative by nature and must not
# trip it.
fn test_the_floor_does_not_block_a_granted_discharge() -> Result[Unit, Str] {
  let c := cap()
  let v2g := { token_id: c.token_id, agent_id: c.agent_id, assets_allow: c.assets_allow, max_shed_w: 40000, min_floor_w: 3000, window_start_ms: c.window_start_ms, window_end_ms: c.window_end_ms, contract: c.contract, review_threshold_w: 0, allow_discharge: true, expires_at_ms: c.expires_at_ms, policy_version: 1 }
  assert_true(models.is_allowed(policy.check(v2g, with_target(0 - 11000), now())), "the import floor does not refuse an export the capability explicitly grants")
}

# ---- Escalation is not denial ------------------------------------------
fn test_a_deep_but_permitted_shed_escalates() -> Result[Unit, Str] {
  match policy.check(cap(), with_target(9000), now()) {
    Escalated(_) => pass(),
    Denied(r) => fail(str.concat("a 13kW shed is within the 15kW cap and should escalate, not be denied: ", r)),
    Allowed => fail("a 13kW shed is at or above the 11kW review threshold and should escalate"),
  }
}

fn test_escalation_is_distinguishable_from_denial() -> Result[Unit, Str] {
  let escalated := policy.check(cap(), with_target(9000), now())
  let denied := policy.check(cap(), with_target(2000), now())
  assert_true(not models.is_allowed(escalated) and not models.is_allowed(denied) and models.verdict_name(escalated) != models.verdict_name(denied), "\"not without a human\" and \"you may not\" are different outcomes")
}

fn test_no_threshold_means_no_escalation() -> Result[Unit, Str] {
  let c := cap()
  let unattended := { token_id: c.token_id, agent_id: c.agent_id, assets_allow: c.assets_allow, max_shed_w: c.max_shed_w, min_floor_w: c.min_floor_w, window_start_ms: c.window_start_ms, window_end_ms: c.window_end_ms, contract: c.contract, review_threshold_w: 0, allow_discharge: c.allow_discharge, expires_at_ms: c.expires_at_ms, policy_version: 1 }
  assert_true(models.is_allowed(policy.check(unattended, with_target(9000), now())), "a capability with no review threshold does not escalate")
}

# ---- Suite -------------------------------------------------------------
#
# `lex test` calls `run_all` and DISCARDS what it returns (lex-lang#757), so a
# returned failure count reports `ok` however many assertions failed. This
# prints each failure by name and then raises.
fn results() -> List[(Str, Result[Unit, Str])] {
  [("the_granted_command_is_allowed", test_the_granted_command_is_allowed()), ("the_real_0314_command_needs_a_human", test_the_real_0314_command_needs_a_human()), ("shed_is_measured_against_the_baseline", test_shed_is_measured_against_the_baseline()), ("raising_the_limit_sheds_nothing", test_raising_the_limit_sheds_nothing()), ("another_asset_is_refused", test_another_asset_is_refused()), ("an_empty_allowlist_grants_nothing", test_an_empty_allowlist_grants_nothing()), ("a_different_contract_is_refused", test_a_different_contract_is_refused()), ("a_window_that_runs_past_the_grant_is_refused", test_a_window_that_runs_past_the_grant_is_refused()), ("a_command_issued_outside_its_own_window_is_refused", test_a_command_issued_outside_its_own_window_is_refused()), ("a_deeper_shed_than_granted_is_refused", test_a_deeper_shed_than_granted_is_refused()), ("a_target_below_the_floor_is_refused", test_a_target_below_the_floor_is_refused()), ("an_expired_capability_is_refused", test_an_expired_capability_is_refused()), ("a_capability_with_no_policy_version_is_refused", test_a_capability_with_no_policy_version_is_refused()), ("discharge_is_refused_without_an_explicit_grant", test_discharge_is_refused_without_an_explicit_grant()), ("discharge_is_allowed_only_when_granted", test_discharge_is_allowed_only_when_granted()), ("the_floor_does_not_block_a_granted_discharge", test_the_floor_does_not_block_a_granted_discharge()), ("a_deep_but_permitted_shed_escalates", test_a_deep_but_permitted_shed_escalates()), ("escalation_is_distinguishable_from_denial", test_escalation_is_distinguishable_from_denial()), ("no_threshold_means_no_escalation", test_no_threshold_means_no_escalation())]
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

fn run_all() -> [io] Unit {
  let failures := report(results())
  if failures == 0 {
    ()
  } else {
    let __p := io.print(str.concat(int.to_str(failures), " test(s) failed"))
    let __boom := raise_failure(0)
    ()
  }
}

