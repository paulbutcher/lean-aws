/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Tests.Fakes

namespace Tests.Container
open Aws.Credentials Tests.Fakes

/-- The check is worth nothing if it merely warns, so what is proved is that a full URI which
passes it is the only kind that yields a request at all. -/
theorem endpointUrl_full_allowed (full url : String) :
    endpointUrl none (some full) = .ok url → endpointAllowed url = true := by
  simp only [endpointUrl]
  split <;> intro h <;> simp_all

private def body : String :=
  "{\"AccessKeyId\":\"AKID\",\"SecretAccessKey\":\"secret\",\"Token\":\"token\"," ++
    "\"Expiration\":\"2026-09-02T15:04:05Z\"}"

private def run (vars : List (String × String)) (files : List (String × String) := [])
    (reply : Except Leancurl.CurlError Leancurl.Response := response 200 body) :
    IO (Array Leancurl.Request × Except Failure Resolved) := do
  let sent ← IO.mkRef #[]
  let result ← (container (env vars files) (http sent reply)).resolve
  return (← sent.get, result)

private def sentUrl (sent : Array Leancurl.Request) : Option String := sent[0]?.map (·.url)

private def sentToken (sent : Array Leancurl.Request) : Option String :=
  sent[0]?.bind (header · "Authorization")

private def relative : List (String × String) :=
  [("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/e4d2")]

private def full : List (String × String) :=
  [("AWS_CONTAINER_CREDENTIALS_FULL_URI", "https://example.com/creds")]

/-! ## The endpoint -/

private def endpointChecks : IO (List (String × Bool)) := do
  let (fromRelative, _) ← run relative
  let (fromFull, _) ← run full
  let (fromBoth, _) ← run (relative ++ full)
  let (refused, refusal) ←
    run [("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://example.com/creds")]
  let (_, absent) ← run []
  return [
      ("a relative URI is resolved against the container agent",
        sentUrl fromRelative == some "http://169.254.170.2/v2/credentials/e4d2"),
      ("a full URI is fetched as it stands", sentUrl fromFull == some "https://example.com/creds"),
      ("a relative URI wins over a full one",
        sentUrl fromBoth == some "http://169.254.170.2/v2/credentials/e4d2"),
      ("neither variable is an absent source", isAbsent absent),
      ("a full URI that is neither https nor local is refused", isBroken refusal),
      ("refusing it means the request is not sent", refused.isEmpty),
      ("http to the container agent is allowed",
        endpointAllowed "http://169.254.170.2/v2/credentials/e4d2"),
      ("http to loopback is allowed",
        endpointAllowed "http://127.0.0.1:8080/creds" && endpointAllowed "http://localhost/creds"),
      ("https to anywhere is allowed", endpointAllowed "https://example.com/creds"),
      ("a name that begins with a loopback address is not one",
        !endpointAllowed "http://127.0.0.1.example.com/creds"),
      ("userinfo does not disguise the host",
        !endpointAllowed "http://169.254.170.2@example.com/creds") ]

/-! ## The token -/

private def tokenChecks : IO (List (String × Bool)) := do
  let (fromVariable, _) ← run (("AWS_CONTAINER_AUTHORIZATION_TOKEN", "opaque") :: full)
  let named := ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "/var/run/token") :: full
  let (fromFile, _) ← run named [("/var/run/token", "opaque\n")]
  let (_, unreadable) ← run named
  let (_, blank) ← run named [("/var/run/token", "\n")]
  let (untokened, _) ← run full
  return [
      ("the token travels as Authorization", sentToken fromVariable == some "opaque"),
      ("the token is read from the file the environment names",
        sentToken fromFile == some "opaque"),
      ("a token file that cannot be read is a misconfiguration", isBroken unreadable),
      ("a token file with nothing in it is a misconfiguration", isBroken blank),
      ("no token, no header", sentToken untokened == none) ]

/-! ## The response -/

private def responseChecks : IO (List (String × Bool)) := do
  let (_, ok) ← run full
  let (_, forbidden) ← run full (reply := response 403 "{}")
  let (_, malformed) ← run full (reply := response 200 "not json")
  let (_, incomplete) ← run full (reply := response 200 "{\"AccessKeyId\":\"AKID\"}")
  let (_, unreadableExpiry) ← run full
    (reply := response 200 (body.replace "2026-09-02T15:04:05Z" "soon"))
  let (_, unreachable) ← run full (reply := .error { code := 7, message := "connection refused" })
  return [
      ("the response is read into credentials", credentialsAre ok "AKID" "secret" (some "token")),
      -- 1788361445 is 2026-09-02T15:04:05Z, confirmed against an independent implementation.
      ("the expiration is read with them", expiresAt ok 1788361445),
      ("a refused request is a broken source", isBroken forbidden),
      ("a response that is not JSON is a broken source", isBroken malformed),
      ("a response missing a field is a broken source", isBroken incomplete),
      ("an expiration that cannot be read is a broken source", isBroken unreadableExpiry),
      ("an endpoint that cannot be reached is a broken source", isBroken unreachable) ]

/-! ## Expiration

Each expected rendering comes from `Timestamp.amzDate`, which reads the civil calendar in the
direction this reads it back, and is checked against the published vectors where this is not.
-/

private def expirationChecks : List (String × Bool) :=
  let rendered (text : String) : Option String :=
    (timestampOfIso8601 text).map Aws.Sigv4.Timestamp.amzDate
  [ ("an expiration is the instant it names",
      rendered "2026-09-02T15:04:05Z" == some "20260902T150405Z"),
    ("the epoch itself", timestampOfIso8601 "1970-01-01T00:00:00Z" == some ⟨0⟩),
    ("a leap day", rendered "2000-02-29T12:00:00Z" == some "20000229T120000Z"),
    ("the day after a century that is not a leap year",
      rendered "2100-03-01T00:00:00Z" == some "21000301T000000Z"),
    ("the fractional seconds some endpoints append",
      timestampOfIso8601 "2026-09-02T15:04:05.123456Z"
        == timestampOfIso8601 "2026-09-02T15:04:05Z"),
    ("an offset other than UTC is refused rather than read as UTC",
      (timestampOfIso8601 "2026-09-02T15:04:05+01:00").isNone),
    ("what is not a timestamp is refused", (timestampOfIso8601 "very soon").isNone) ]

public def checks : IO (List (String × Bool)) := do
  return (← endpointChecks) ++ (← tokenChecks) ++ (← responseChecks) ++ expirationChecks

end Tests.Container
