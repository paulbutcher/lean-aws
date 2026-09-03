/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import AwsCredentials

/-!
The seams, stood in for. Nothing here reaches a network or a clock, which is what lets expiry be
tested by moving the one below rather than by waiting for it.
-/

public section

namespace Tests.Fakes
open Aws.Credentials

def env (vars : List (String × String)) (files : List (String × String) := []) : Env IO where
  get name := return vars.lookup name
  readFile path := return match files.lookup path with
    | some contents => .ok contents
    | none => .error "no such file"

def http (sent : IO.Ref (Array Leancurl.Request))
    (reply : Except Leancurl.CurlError Leancurl.Response) : Http IO where
  send request := do
    sent.modify (·.push request)
    return reply

def response (status : UInt32) (body : String) : Except Leancurl.CurlError Leancurl.Response :=
  .ok { status, headers := [], body := body.toUTF8 }

def clock (seconds : IO.Ref Nat) : Clock IO where
  now := return ⟨← seconds.get⟩

/-- Answers each reply in turn, and counts, so that a test says how many times the cache in front
of it resolved rather than what it resolved to. -/
def scripted (calls : IO.Ref Nat) (replies : List (Except Failure Resolved)) : Provider IO where
  resolve := do
    let call ← calls.modifyGet fun call => (call, call + 1)
    return replies[call]?.getD (.error (.broken "the test supplied no further replies"))

def resolved (expiration : Option Nat) : Resolved :=
  { credentials := { accessKeyId := "AKID", secretAccessKey := "secret" }
    expiration := expiration.map (⟨·⟩) }

def isAbsent : Except Failure Resolved → Bool
  | .error (.absent _) => true
  | _ => false

def isBroken : Except Failure Resolved → Bool
  | .error (.broken _) => true
  | _ => false

/-- Compares rather than prints: a check that renders credentials into its output defeats the
redaction `Repr Credentials` exists for. -/
def credentialsAre (result : Except Failure Resolved) (accessKeyId secretAccessKey : String)
    (sessionToken : Option String := none) : Bool :=
  match result with
  | .ok resolved => resolved.credentials == { accessKeyId, secretAccessKey, sessionToken }
  | .error _ => false

def expiresAt (result : Except Failure Resolved) (epochSeconds : Nat) : Bool :=
  match result with
  | .ok resolved => resolved.expiration == some ⟨epochSeconds⟩
  | .error _ => false

def header (request : Leancurl.Request) (name : String) : Option String :=
  (request.headers.find? fun h => h.1 == name).map (·.2)

end Tests.Fakes
