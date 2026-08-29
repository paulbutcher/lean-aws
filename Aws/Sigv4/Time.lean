/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public section

namespace Aws.Sigv4

structure Timestamp where
  epochSeconds : Nat
  deriving DecidableEq, Repr, Inhabited

namespace Timestamp

def digitChar (n : Nat) : Char := Char.ofNat (48 + n % 10)

/-- Truncates above two digits, which every caller satisfies: these render a month, day, hour,
minute or second. -/
@[expose] def pad2 (n : Nat) : String := String.ofList [digitChar (n / 10), digitChar n]

@[expose] def pad4 (n : Nat) : String :=
  String.ofList [digitChar (n / 1000), digitChar (n / 100), digitChar (n / 10), digitChar n]

/-- Shifting the epoch to the start of a 400-year era removes every leap year special case,
century rules included, leaving plain division. -/
def civil (days : Nat) : Nat × Nat × Nat :=
  let z := days + 719468
  let era := z / 146097
  let doe := z - era * 146097
  let yoe := (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
  let doy := doe - (365 * yoe + yoe / 4 - yoe / 100)
  let mp := (5 * doy + 2) / 153
  let d := doy - (153 * mp + 2) / 5 + 1
  let m := if mp < 10 then mp + 3 else mp - 9
  (yoe + era * 400 + (if m ≤ 2 then 1 else 0), m, d)

/-- `YYYYMMDD`, the date half of the credential scope. -/
@[expose] def dateStamp (t : Timestamp) : String :=
  let c := civil (t.epochSeconds / 86400)
  pad4 c.1 ++ pad2 c.2.1 ++ pad2 c.2.2

/-- `YYYYMMDDTHHMMSSZ`, always UTC; there is no configuration for this. Built from `dateStamp` so
that the scope and the timestamp cannot disagree, which they would if each read a clock: a
signature that fails for one second a day is the kind of defect that reaches production and
stays there. -/
@[expose] def amzDate (t : Timestamp) : String :=
  let inDay := t.epochSeconds % 86400
  t.dateStamp ++ "T" ++ pad2 (inDay / 3600) ++ pad2 (inDay / 60 % 60) ++ pad2 (inDay % 60) ++ "Z"

end Timestamp

end Aws.Sigv4
