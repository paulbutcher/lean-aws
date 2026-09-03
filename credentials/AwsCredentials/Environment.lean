/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import AwsCredentials.Provider

public section

namespace Aws.Credentials

/--
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, with `AWS_SESSION_TOKEN` where the credentials
are temporary.

Both of the pair or neither. One without the other is a misconfiguration rather than an absent
source, and answering absence to it sends the chain on to fail at the container endpoint, which
is not the thing anyone has to fix.
-/
def environment {m : Type → Type} [Monad m] (env : Env m) : Provider m where
  resolve := do
    match ← env.lookup "AWS_ACCESS_KEY_ID", ← env.lookup "AWS_SECRET_ACCESS_KEY" with
    | none, none =>
      return .error (.absent
        "the environment sets neither AWS_ACCESS_KEY_ID nor AWS_SECRET_ACCESS_KEY")
    | some _, none =>
      return .error (.broken "the environment sets AWS_ACCESS_KEY_ID without AWS_SECRET_ACCESS_KEY")
    | none, some _ =>
      return .error (.broken "the environment sets AWS_SECRET_ACCESS_KEY without AWS_ACCESS_KEY_ID")
    | some accessKeyId, some secretAccessKey =>
      let sessionToken ← env.lookup "AWS_SESSION_TOKEN"
      return .ok { credentials := { accessKeyId, secretAccessKey, sessionToken } }

end Aws.Credentials
