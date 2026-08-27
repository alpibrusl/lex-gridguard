# Capability token: an Ed25519-signed grid-command capability.
#
# Format:  base64url(capability_json) "." base64url(signature)
#
# Same asymmetric guarantee lex-guard relies on for money: the issuer holds the
# 32-byte secret seed, while every aggregator and every enforcement point holds
# only the public key. A compromised aggregator can present a token it was
# given; it cannot mint one that grants more.
#
# That matters more here than it does for a budget. A forged spending token
# costs money. A forged grid capability moves power on someone else's physical
# asset — and for a bidirectional charger, discharges someone's vehicle.

import "std.str" as str

import "std.json" as json

import "std.bytes" as bytes

import "std.crypto" as crypto

import "std.list" as list

import "lex-crypto/ed25519" as ed

import "./models" as models

type CapabilityToken = { raw :: Str, capability :: models.Capability }

# Issue a token: sign `cap` with a 32-byte Ed25519 secret seed. Lives here so
# the package is self-contained and testable end to end; a real control plane
# calls the same function.
fn issue(secret :: Bytes, cap :: models.Capability) -> [crypto] Result[Str, Str] {
  let payload := json.stringify(cap)
  let payload_b64 := crypto.base64url_encode(bytes.from_str(payload))
  match ed.sign_text(secret, payload) {
    Err(e) => Err(e),
    Ok(sig_b64) => Ok(str.concat(payload_b64, str.concat(".", sig_b64))),
  }
}

# Verify a token against the issuer's base64url public key, returning the
# capability it carries.
#
# The signature is checked over the DECODED payload before the payload is
# trusted for anything else, and the capability is parsed only after that
# check passes — so a malformed or unsigned token can never reach the policy.
fn verify(public_b64 :: Str, token :: Str) -> [crypto] Result[CapabilityToken, Str] {
  let parts := str.split(token, ".")
  if list.len(parts) != 2 {
    Err("malformed capability token")
  } else {
    let payload_b64 := match list.head(parts) {
      Some(s) => s,
      None => "",
    }
    let sig := match list.head(list.tail(parts)) {
      Some(s) => s,
      None => "",
    }
    match crypto.base64url_decode(payload_b64) {
      Err(_) => Err("capability token payload is not valid base64url"),
      Ok(payload_bytes) => match bytes.to_str(payload_bytes) {
        Err(_) => Err("capability token payload is not valid UTF-8"),
        Ok(payload) => if not ed.verify_text(public_b64, payload, sig) {
          Err("capability token signature is not valid for this issuer")
        } else {
          match (json.parse(payload) :: Result[models.Capability, Str]) {
            Err(_) => Err("capability token payload is not a capability"),
            Ok(cap) => Ok({ raw: token, capability: cap }),
          }
        },
      },
    }
  }
}

