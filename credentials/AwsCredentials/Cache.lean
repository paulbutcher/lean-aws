/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import AwsCredentials.Provider

public section

namespace Aws.Credentials

/-- Far enough ahead of the expiry that a request signed with credentials this answered has time
to be sent and answered before they stop working. -/
def refreshMargin : Nat := 300

/--
Holds what the inner provider last answered and asks it again once the clock passes the refresh
point, which is `refreshMargin` seconds before the expiry rather than the expiry itself.

Credentials with no expiry, which is what the environment supplies, are held and never resolved
again: nothing changes them under a running process.

A refresh that fails while the credentials it holds are still valid answers those, because a
transient failure inside the margin is exactly what the margin is for and reporting it would
throw away credentials that still work.
-/
def Provider.cached {m : Type → Type} [Monad m] [MonadLiftT BaseIO m] (clock : Clock m)
    (inner : Provider m) (margin : Nat := refreshMargin) : m (Provider m) := do
  let held : IO.Ref (Option Resolved) ← liftM (IO.mkRef none)
  return {
    resolve := do
      let now ← clock.now
      let last ← liftM (held.get : BaseIO (Option Resolved))
      let fresh := last.filter fun resolved =>
        resolved.expiration.all fun expiry => now.epochSeconds + margin < expiry.epochSeconds
      match fresh with
      | some resolved => return .ok resolved
      | none =>
        match ← inner.resolve with
        | .ok resolved =>
          liftM (held.set (some resolved) : BaseIO Unit)
          return .ok resolved
        | .error failure =>
          match last.filter (·.expiration.all (now.epochSeconds < ·.epochSeconds)) with
          | some resolved => return .ok resolved
          | none => return .error failure }

end Aws.Credentials
