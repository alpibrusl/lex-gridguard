# policy.lex — the stateless half of the gate.
#
# Given a capability and a command, may it proceed? Pure: no clock, no database,
# no network. Everything it needs is in its arguments, so the same check runs at
# the enforcement boundary, in a test, or in a counterparty's own re-run of a
# disputed decision, and produces the same answer.
#
# Order matters. The checks run from the most fundamental to the most
# quantitative — is this capability even valid, is it for this asset and
# contract, is it in force now, and only then how deep the command goes. A
# denial should name the first thing that was wrong, not the last.

import "std.str" as str

import "std.int" as int

import "std.list" as list

import "./models" as models

fn allows_asset(cap :: models.Capability, asset :: Str) -> Bool {
  list.fold(cap.assets_allow, false, fn (acc :: Bool, a :: Str) -> Bool {
    acc or a == asset
  })
}

# The command's window must sit inside the capability's, not merely overlap it.
# An overlapping window would let a capability for 03:00-04:00 authorise a
# curtailment running until dawn.
fn window_within(cap :: models.Capability, cmd :: models.Command) -> Bool {
  cmd.window_start_ms >= cap.window_start_ms and cmd.window_end_ms <= cap.window_end_ms
}

# How deep the command cuts, as a positive magnitude. A command that raises the
# limit sheds nothing.
fn shed_w(cmd :: models.Command) -> Int {
  let d := cmd.baseline_w - cmd.target_w
  if d < 0 {
    0
  } else {
    d
  }
}

fn is_discharge(cmd :: models.Command) -> Bool {
  cmd.target_w < 0
}

fn w(n :: Int) -> Str {
  str.concat(int.to_str(n), "W")
}

# Evaluate. `now_ms` is passed in rather than read, so this stays pure and a
# disputed decision can be re-run at the time it was made.
fn check(cap :: models.Capability, cmd :: models.Command, now_ms :: Int) -> models.Verdict {
  if cap.policy_version <= 0 {
    Denied("capability has no policy version")
  } else {
    if cap.expires_at_ms > 0 and now_ms >= cap.expires_at_ms {
      Denied("capability expired")
    } else {
      if not allows_asset(cap, cmd.asset) {
        Denied(str.concat("capability does not cover asset ", cmd.asset))
      } else {
        if cap.contract != cmd.contract {
          Denied(str.concat("command cites contract ", str.concat(cmd.contract, str.concat(", capability is for ", cap.contract))))
        } else {
          if not window_within(cap, cmd) {
            Denied("command window falls outside the contracted window")
          } else {
            if now_ms < cmd.window_start_ms or now_ms >= cmd.window_end_ms {
              Denied("command issued outside its own window")
            } else {
              check_magnitude(cap, cmd)
            }
          }
        }
      }
    }
  }
}

# The quantitative half, once the command is established as in-scope.
fn check_magnitude(cap :: models.Capability, cmd :: models.Command) -> models.Verdict {
  if is_discharge(cmd) and not cap.allow_discharge {
    Denied("capability does not permit discharge")
  } else {
    let shed := shed_w(cmd)
    if shed > cap.max_shed_w {
      Denied(str.concat("shed of ", str.concat(w(shed), str.concat(" exceeds the permitted ", w(cap.max_shed_w)))))
    } else {
      if not is_discharge(cmd) and cmd.target_w < cap.min_floor_w {
        Denied(str.concat("target of ", str.concat(w(cmd.target_w), str.concat(" is below the floor of ", w(cap.min_floor_w)))))
      } else {
        if cap.review_threshold_w > 0 and shed >= cap.review_threshold_w {
          Escalated(str.concat("shed of ", str.concat(w(shed), str.concat(" is at or above the review threshold of ", w(cap.review_threshold_w)))))
        } else {
          Allowed
        }
      }
    }
  }
}

