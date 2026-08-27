# lex-gridguard data model.
#
# The sentence this package exists to enforce:
#
#   "Aggregator A may curtail asset B by at most X kW, inside window W, under
#    contract C — and nothing else."
#
# `Capability` is that sentence as data, carried inside a signed token. `Command`
# is a single request evaluated against it. Everything is compared exactly:
# power in whole watts and time in epoch milliseconds, so a policy check is
# integer arithmetic with no rounding to argue about afterwards. Callers convert
# from kW at the edges.
#
# Why watts rather than kW: a curtailment settles as money, and a float
# comparison that is off by an ulp at the boundary is a dispute. The whole point
# of the package is to remove arguments, so the comparison has to be exact.
# What an issuer grants. Signed into a capability token (see token.lex).
#
#   assets_allow      the assets this capability covers; empty means none, NOT
#                     all — a capability that grants nothing is safe, one that
#                     silently grants everything is not
#   max_shed_w        the deepest curtailment permitted, in watts, as a
#                     magnitude (0 forbids curtailment entirely)
#   min_floor_w       the lowest power the asset may be left at; a command that
#                     would drop it below this is refused even if the shed
#                     depth is within cap. Protects an asset from being
#                     curtailed to a standstill by a technically-valid command
#   window_start_ms   the contracted window, inclusive of start, exclusive of
#   window_end_ms     end. A command's own window must sit INSIDE this one
#   review_threshold_w  at or above this depth the command needs a human
#                     (0 disables the human gate)
#   allow_discharge   whether this capability may command EXPORT at all.
#                     Discharging someone's vehicle is a different act from
#                     throttling its charge rate, so it is a separate grant and
#                     defaults to off by construction — a capability written for
#                     curtailment can never be read as permission to discharge

type Capability = { token_id :: Str, agent_id :: Str, assets_allow :: List[Str], max_shed_w :: Int, min_floor_w :: Int, window_start_ms :: Int, window_end_ms :: Int, contract :: Str, review_threshold_w :: Int, allow_discharge :: Bool, expires_at_ms :: Int, policy_version :: Int }

# A single grid command, evaluated against a capability.
#
#   target_w    the power the asset is being told to hold. Positive is import
#               (charging), negative is export (discharge/V2G)
#   baseline_w  what it would otherwise have drawn — the shed depth is
#               `baseline_w - target_w`, which is what the cap applies to
type Command = { asset :: Str, target_w :: Int, baseline_w :: Int, window_start_ms :: Int, window_end_ms :: Int, contract :: Str, reason :: Str }

# The outcome of evaluating a command.
#
# `Escalated` is deliberately NOT a denial: the command is within policy but
# deep enough to need a person. Collapsing it into Denied would lose the
# distinction between "you may not" and "not without a human", which is exactly
# the distinction an operator needs at 03:14.
#
# `Decision` below is what a gate call returns and what lands on the trail: the
# verdict, the event that records it, and how deep the command actually cut.
# (Its own comment lives up here because `lex fmt` deletes a comment sitting
# between a variant type and what follows it — lex-lang#755.)
type Verdict = Allowed | Escalated(Str) | Denied(Str)

type Decision = { verdict :: Verdict, event_id :: Str, shed_w :: Int }

fn is_allowed(v :: Verdict) -> Bool {
  match v {
    Allowed => true,
    Escalated(_) => false,
    Denied(_) => false,
  }
}

fn reason_of(v :: Verdict) -> Str {
  match v {
    Allowed => "",
    Escalated(r) => r,
    Denied(r) => r,
  }
}

fn verdict_name(v :: Verdict) -> Str {
  match v {
    Allowed => "allowed",
    Escalated(_) => "escalated",
    Denied(_) => "denied",
  }
}

