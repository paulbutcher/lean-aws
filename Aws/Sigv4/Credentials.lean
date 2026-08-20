/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public section

namespace Aws.Sigv4

/--
Static credentials, temporary ones included. Resolving them from the environment, the shared
config file, or the instance metadata service is IO and is the caller's.
-/
structure Credentials where
  accessKeyId : String
  secretAccessKey : String
  /-- Present for credentials from an assumed role. It travels as `X-Amz-Security-Token` and is
  signed: omitting it from the signed set is accepted by some services and rejected by others,
  which makes it a defect that surfaces only after a deployment moves to temporary credentials. -/
  sessionToken : Option String := none
  deriving DecidableEq

/-- Renders neither the secret nor the session token. A signer that prints its own credentials
into a stack trace has done more harm than an unsigned request would. -/
instance : Repr Credentials where
  reprPrec c _ := Std.Format.text s!"Credentials({c.accessKeyId}, <redacted>)"

/-- Region and service are separate fields because they are two strings of the same shape, and
transposing them yields a signature mismatch with no clue as to why. -/
structure SigningScope where
  region : String
  service : String
  deriving DecidableEq, Repr, Inhabited

end Aws.Sigv4
