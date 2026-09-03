/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Tests.Fakes

namespace Tests.Environment
open Aws.Credentials Tests.Fakes

private def resolve (vars : List (String × String)) : IO (Except Failure Resolved) :=
  (environment (env vars)).resolve

public def checks : IO (List (String × Bool)) := do
  let pair := [("AWS_ACCESS_KEY_ID", "AKID"), ("AWS_SECRET_ACCESS_KEY", "secret")]
  let temporary ← resolve (("AWS_SESSION_TOKEN", "token") :: pair)
  let permanent ← resolve pair
  let keyOnly ← resolve [("AWS_ACCESS_KEY_ID", "AKID")]
  let secretOnly ← resolve [("AWS_SECRET_ACCESS_KEY", "secret")]
  let neither ← resolve []
  let empty ← resolve [("AWS_ACCESS_KEY_ID", ""), ("AWS_SECRET_ACCESS_KEY", "")]
  return [
      ("all three variables are read", credentialsAre temporary "AKID" "secret" (some "token")),
      ("credentials without a session token are read", credentialsAre permanent "AKID" "secret"),
      ("permanent credentials carry no expiry",
        match permanent with | .ok resolved => resolved.expiration.isNone | .error _ => false),
      ("a key with no secret is a misconfiguration, not an absent source", isBroken keyOnly),
      ("a secret with no key is a misconfiguration, not an absent source", isBroken secretOnly),
      ("neither variable is an absent source", isAbsent neither),
      ("a variable set to nothing is a variable unset", isAbsent empty) ]

end Tests.Environment
