/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Tests.Fakes

namespace Tests.Chain
open Aws.Credentials Tests.Fakes

private def containerVars : List (String × String) :=
  [("AWS_CONTAINER_CREDENTIALS_FULL_URI", "https://example.com/creds")]

private def body : String :=
  "{\"AccessKeyId\":\"AKID\",\"SecretAccessKey\":\"secret\",\"Token\":\"token\"," ++
    "\"Expiration\":\"2026-09-02T15:04:05Z\"}"

private def resolve (vars : List (String × String)) :
    IO (Array Leancurl.Request × Except Failure Resolved) := do
  let sent ← IO.mkRef #[]
  let sources := env vars
  let result ← (Provider.chain
    [environment sources, container sources (http sent (response 200 body))]).resolve
  return (← sent.get, result)

public def checks : IO (List (String × Bool)) := do
  let (_, fellThrough) ← resolve containerVars
  let (asked, stopped) ← resolve (("AWS_ACCESS_KEY_ID", "AKID") :: containerVars)
  let (_, exhausted) ← resolve []
  return [
      ("an absent source falls through to the next",
        credentialsAre fellThrough "AKID" "secret" (some "token")),
      ("a broken source stops the chain", isBroken stopped),
      ("a broken source stops it before the next source is asked", asked.isEmpty),
      ("a chain of absent sources is itself absent", isAbsent exhausted) ]

end Tests.Chain
