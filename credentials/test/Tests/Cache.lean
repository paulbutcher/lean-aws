/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Tests.Fakes

/-!
Expiry, moved past rather than waited for. The refresh point is `refreshMargin` seconds before the
expiry, so a cache holding credentials that expire at 1000 resolves again at 700.
-/

namespace Tests.Cache
open Aws.Credentials Tests.Fakes

private def cache (replies : List (Except Failure Resolved)) :
    IO (IO.Ref Nat × IO.Ref Nat × Provider IO) := do
  let seconds ← IO.mkRef 0
  let calls ← IO.mkRef 0
  return (seconds, calls, ← Provider.cached (clock seconds) (scripted calls replies))

public def checks : IO (List (String × Bool)) := do
  let (seconds, calls, refreshing) ←
    cache [.ok (resolved (some 1000)), .ok (resolved (some 2000))]
  let _ ← refreshing.resolve
  seconds.set 699
  let _ ← refreshing.resolve
  let beforeRefreshPoint ← calls.get
  seconds.set 700
  let refreshed ← refreshing.resolve
  let atRefreshPoint ← calls.get

  let (failing, _, unreliable) ←
    cache [.ok (resolved (some 1000)), .error (.broken "unreachable")]
  let _ ← unreliable.resolve
  failing.set 800
  let stale ← unreliable.resolve
  failing.set 1001
  let expired ← unreliable.resolve

  let (later, permanentCalls, permanent) ← cache [.ok (resolved none)]
  let _ ← permanent.resolve
  later.set 31536000
  let _ ← permanent.resolve
  let resolutions ← permanentCalls.get

  return [
      ("credentials are held until the refresh point", beforeRefreshPoint == 1),
      ("the refresh point passes and they are resolved again", atRefreshPoint == 2),
      ("what the refresh answered is what is held", expiresAt refreshed 2000),
      ("a refresh that fails inside the margin answers the credentials it holds",
        credentialsAre stale "AKID" "secret" && expiresAt stale 1000),
      ("a refresh that fails past the expiry reports the failure", isBroken expired),
      ("credentials with no expiry are never resolved again", resolutions == 1) ]

end Tests.Cache
