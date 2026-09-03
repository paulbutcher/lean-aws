/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Aws.Sigv4
public import Leancurl
import Std.Time

public section

namespace Aws.Credentials

/--
Why a source produced no credentials. The distinction is the chain's: a source nothing configured
is one to pass over, and a source configured wrongly is one to stop at, because the next source's
failure would name something the operator has no reason to change.
-/
inductive Failure where
  | absent (message : String)
  | broken (message : String)
  deriving Repr, DecidableEq

/-- Every message names the variable or the endpoint it wanted, and never a value it read: a
credential that reaches a log has outlived every access control put in front of it. -/
def Failure.text : Failure → String
  | .absent message | .broken message => message

/-- Credentials and the instant they stop working. -/
structure Resolved where
  credentials : Sigv4.Credentials
  /-- Absent where nothing revokes them under a running process, which is what the environment
  supplies. -/
  expiration : Option Sigv4.Timestamp := none
  deriving Repr

/-- A source, a chain of sources, and a cache in front of one are all this, which is what lets
them compose in any order. -/
structure Provider (m : Type → Type) where
  resolve : m (Except Failure Resolved)

/-- What a signer needs. The distinction between an absent source and a broken one has been used
by the time a caller gets here, so what is left of it is the message. -/
def Provider.credentials {m : Type → Type} [Functor m] (p : Provider m) :
    m (Except String Sigv4.Credentials) :=
  (fun result => (result.map (·.credentials)).mapError Failure.text) <$> p.resolve

private def chainFrom {m : Type → Type} [Monad m] :
    List (Provider m) → List String → m (Except Failure Resolved)
  | [], [] => pure (.error (.absent "the chain has no sources"))
  | [], skipped => pure (.error (.absent (String.intercalate "; " skipped.reverse)))
  | source :: rest, skipped => do
    match ← source.resolve with
    | .ok resolved => pure (.ok resolved)
    | .error (.broken message) => pure (.error (.broken message))
    | .error (.absent message) => chainFrom rest (message :: skipped)

/-- Stops at the first source that answers and at the first that is broken. Falling past a broken
source would mask the misconfiguration behind the last source's less specific failure. -/
def Provider.chain {m : Type → Type} [Monad m] (sources : List (Provider m)) : Provider m where
  resolve := chainFrom sources []

/-! ## Seams

Each is a record rather than a class, so a test supplies a different one by passing it rather than
by arranging for a different instance to be found.
-/

structure Clock (m : Type → Type) where
  now : m Sigv4.Timestamp

structure Http (m : Type → Type) where
  send : Leancurl.Request → m (Except Leancurl.CurlError Leancurl.Response)

/-- The environment and the files it names, together: the container token arrives as either, and
what supplies one supplies the other. -/
structure Env (m : Type → Type) where
  get : String → m (Option String)
  readFile : String → m (Except String String)

/-- A variable set to nothing is a variable unset. Taken literally, an empty access key id is one
to sign with, and the rejection that follows says nothing about which variable was blank. -/
def Env.lookup {m : Type → Type} [Functor m] (env : Env m) (name : String) : m (Option String) :=
  (fun value => value.filter (!·.trimAscii.isEmpty)) <$> env.get name

def systemClock : Clock IO where
  now := do
    let now ← Std.Time.Timestamp.now
    return ⟨now.toSecondsSinceUnixEpoch.toInt.toNat⟩

def curlHttp : Http IO where
  send := Leancurl.Curl.send

def ioEnv : Env IO where
  get name := IO.getEnv name
  readFile path := do
    match ← (IO.FS.readFile path).toBaseIO with
    | .ok contents => return .ok contents
    | .error e => return .error (toString e)

end Aws.Credentials
