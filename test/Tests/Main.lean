/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Tests

/-!
The theorems pass by compiling. What runs here are the published vectors, and the cases whose
expectation is a rule rather than a proof.
-/

def main : IO UInt32 := do
  let checks := Tests.Suite.checks ++ Tests.Vectors.checks ++ Tests.Canonical.checks
    ++ Tests.Encoding.checks
    ++ Tests.Time.checks
  let failed := checks.filter fun (_, passed) => !passed
  for (name, _) in failed do
    IO.eprintln s!"FAILED: {name}"
  if failed.isEmpty then
    IO.println s!"{checks.length} checks passed"
    return 0
  else
    IO.eprintln s!"{failed.length} of {checks.length} checks failed"
    return 1
