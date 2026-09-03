/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import AwsCredentials.Provider
public import Json

public section

namespace Aws.Credentials

/-! ## The endpoint -/

/-- The address the ECS agent answers on, which a relative URI is resolved against. -/
def containerHost : String := "http://169.254.170.2"

private def splitOnce (separator text : String) : Option (String × String) :=
  match text.splitOn separator with
  | before :: first :: rest => some (before, separator.intercalate (first :: rest))
  | _ => none

/-- Scheme and host, lowercased, with userinfo, port and any IPv6 brackets removed. -/
def uriParts (uri : String) : Option (String × String) := do
  let (scheme, afterScheme) ← splitOnce "://" uri
  let authority := (afterScheme.takeWhile fun c => c != '/' && c != '?' && c != '#').toString
  let hostAndPort := (authority.splitOn "@").getLastD authority
  let host :=
    if hostAndPort.startsWith "[" then ((hostAndPort.drop 1).takeWhile (· != ']')).toString
    else (hostAndPort.takeWhile (· != ':')).toString
  if scheme.isEmpty || host.isEmpty then none else some (scheme.toLower, host.toLower)

private def octets (host : String) : Option (List Nat) :=
  let parts := host.splitOn "."
  if parts.length == 4 then
    parts.mapM fun part =>
      match part.toNat? with
      | some value => if part.isEmpty || part.length > 3 || value > 255 then none else some value
      | none => none
  else none

/--
Loopback and link-local, which is where a container credentials endpoint lives.

A name matches only as `localhost`, and an address only when it is four numbers:
`127.0.0.1.example.com` resolves to wherever its owner points it. Of the link-local IPv6 range
only `fe80:` is matched, which refuses more than it need but never less.
-/
def isTrustedHost (host : String) : Bool :=
  match octets host with
  | some [first, second, _, _] => first == 127 || (first == 169 && second == 254)
  | _ => host == "localhost" || host == "::1" || host.startsWith "fe80:"

/-- What the SDKs enforce, and for the reason they enforce it: the request carries the container
authorization token, and without this an environment variable is enough to have the token sent
wherever whoever set it chose. -/
def endpointAllowed (uri : String) : Bool :=
  match uriParts uri with
  | some (scheme, host) => scheme == "https" || isTrustedHost host
  | none => false

/-- Pure, so that a refused URI is a value a test reads rather than a request it has to establish
was never sent. -/
@[expose] def endpointUrl (relative full : Option String) : Except Failure String :=
  match relative, full with
  | some path, _ =>
    .ok (containerHost ++ (if path.startsWith "/" then path else "/" ++ path))
  | none, some uri =>
    if endpointAllowed uri then .ok uri
    else .error (.broken <|
      "AWS_CONTAINER_CREDENTIALS_FULL_URI names neither an https endpoint nor a loopback or " ++
      "link-local host, and the container authorization token may not travel to one")
  | none, none =>
    .error (.absent <|
      "the environment sets neither AWS_CONTAINER_CREDENTIALS_RELATIVE_URI nor " ++
      "AWS_CONTAINER_CREDENTIALS_FULL_URI")

def endpointRequest (url : String) (token : Option String) : Leancurl.Request :=
  { url
    headers := match token with
      | some token => [("Authorization", token)]
      | none => []
    -- The endpoint is on the same host, so a request that has not answered in five seconds is
    -- not going to. Waiting on it holds up whatever asked to be signed.
    timeoutMs := some 5000 }

/-! ## The response -/

private def number (digits : List Char) : Option Nat :=
  digits.foldlM (fun value c => if c.isDigit then some (value * 10 + (c.toNat - 48)) else none) 0

/-- Shifting the epoch to the start of a 400-year era removes every leap year special case,
century rules included; `Timestamp.civil` reads the same rearrangement in the other direction. -/
private def daysFromCivil (year month day : Nat) : Nat :=
  let shifted := if month ≤ 2 then year - 1 else year
  let era := shifted / 400
  let yearOfEra := shifted - era * 400
  let dayOfYear := (153 * (if month > 2 then month - 3 else month + 9) + 2) / 5 + day - 1
  let dayOfEra := yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
  era * 146097 + dayOfEra - 719468

private def isUtcTail : List Char → Bool
  | [] => true
  | ['Z'] => true
  | '.' :: first :: rest =>
    let after := rest.dropWhile Char.isDigit
    first.isDigit && (after.isEmpty || after == ['Z'])
  | _ => false

/--
`YYYY-MM-DDTHH:MM:SSZ`, with the fractional seconds some endpoints append.

An offset other than UTC is refused rather than read as one. No container endpoint sends one, and
credentials believed to last an hour longer than they do are the failure this package exists to
prevent.
-/
def timestampOfIso8601 (text : String) : Option Sigv4.Timestamp :=
  match text.toUpper.toList with
  | y3 :: y2 :: y1 :: y0 :: '-' :: mo1 :: mo0 :: '-' :: d1 :: d0 :: 'T' ::
      h1 :: h0 :: ':' :: mi1 :: mi0 :: ':' :: s1 :: s0 :: rest => do
    let year ← number [y3, y2, y1, y0]
    let month ← number [mo1, mo0]
    let day ← number [d1, d0]
    let hour ← number [h1, h0]
    let minute ← number [mi1, mi0]
    let second ← number [s1, s0]
    guard (isUtcTail rest)
    guard (1970 ≤ year && 1 ≤ month && month ≤ 12 && 1 ≤ day && day ≤ 31)
    -- A leap second is a second sixty, and rolling it into the next minute is what every
    -- consumer of this does with it.
    guard (hour < 24 && minute < 60 && second ≤ 60)
    some ⟨daysFromCivil year month day * 86400 + hour * 3600 + minute * 60 + second⟩
  | _ => none

private def field (body : Json) (name : String) : Except Failure String :=
  match (body.getObjVal? name).bind Json.getStr? with
  | .ok value => .ok value
  | .error _ => .error (.broken s!"the container credentials response carries no string {name}")

/-- Every field is required, `Expiration` included. Credentials the endpoint rotates, held with no
expiry because the field naming it was unreadable, are what a cache in front of this would then
answer with for the life of the process. -/
def resolvedOfJson (body : Json) : Except Failure Resolved := do
  let accessKeyId ← field body "AccessKeyId"
  let secretAccessKey ← field body "SecretAccessKey"
  let token ← field body "Token"
  let expiration ← field body "Expiration"
  match timestampOfIso8601 expiration with
  | none =>
    .error (.broken "the container credentials response carries an Expiration this cannot read")
  | some expiration =>
    .ok { credentials := { accessKeyId, secretAccessKey, sessionToken := some token }
          expiration := some expiration }

def resolvedOfResponse (response : Leancurl.Response) : Except Failure Resolved :=
  if response.status != 200 then
    .error (.broken s!"the container credentials endpoint answered {response.status}")
  else
    match String.fromUTF8? response.body with
    | none =>
      .error (.broken "the container credentials endpoint answered bytes that are not UTF-8")
    | some text =>
      match Json.parse text with
      | .error _ =>
        .error (.broken "the container credentials endpoint answered what is not JSON")
      | .ok body => resolvedOfJson body

private def authorizationToken {m : Type → Type} [Monad m] (env : Env m) :
    m (Except Failure (Option String)) := do
  match ← env.lookup "AWS_CONTAINER_AUTHORIZATION_TOKEN" with
  | some token => return .ok (some token)
  | none =>
    match ← env.lookup "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE" with
    | none => return .ok none
    | some path =>
      match ← env.readFile path with
      | .error reason =>
        return .error (.broken
          s!"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE names a file that could not be read: {reason}")
      | .ok contents =>
        let token := contents.trimAscii.toString
        if token.isEmpty then
          return .error (.broken
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE names a file with no token in it")
        else
          return .ok (some token)

/--
The endpoint a task role is supplied through on ECS and Fargate:
`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` resolved against the container agent, or
`AWS_CONTAINER_CREDENTIALS_FULL_URI` as given, with
`AWS_CONTAINER_AUTHORIZATION_TOKEN` or the contents of the file named by
`AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` as the `Authorization` header.

The credentials it returns expire and are replaced. `Provider.cached` is what honours that.
-/
def container {m : Type → Type} [Monad m] (env : Env m) (http : Http m) : Provider m where
  resolve := do
    let relative ← env.lookup "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
    let full ← env.lookup "AWS_CONTAINER_CREDENTIALS_FULL_URI"
    match endpointUrl relative full with
    | .error failure => return .error failure
    | .ok url =>
      match ← authorizationToken env with
      | .error failure => return .error failure
      | .ok token =>
        match ← http.send (endpointRequest url token) with
        | .error error =>
          return .error (.broken
            s!"the container credentials endpoint could not be reached: {error.message}")
        | .ok response => return resolvedOfResponse response

end Aws.Credentials
