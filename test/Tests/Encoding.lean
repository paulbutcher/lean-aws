/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Aws.Sigv4

/-!
Percent-encoding, which the canonical request is built out of.

Hex round-tripping and lowercase output belong to `leancrypto` and are proved beside their
definitions there. What is proved here is the part this library decides: which bytes escape, what
an escape may contain, and that a canonical URI is absolute however the path normalises.

`Tests.Suite` is the authority on what the encoder should produce, so what the checks below add is
the boundaries it does not reach: a path with no segments, and a parameter with no value.
-/

namespace Tests.Encoding
open Aws.Sigv4

theorem encodeByte_unreserved (b : UInt8) (h : isUnreserved b = true) :
    encodeByte b = [Char.ofNat b.toNat] := by
  simp [encodeByte, h]

theorem length_encodeByte_reserved (b : UInt8) (h : isUnreserved b = false) :
    (encodeByte b).length = 3 := by
  simp [encodeByte, h]

set_option maxRecDepth 8000

/-- Nothing the encoder emits needs encoding itself, which is what makes a second pass over an
already-encoded path well defined rather than a pass over arbitrary bytes. -/
theorem encodeByte_ascii :
    ∀ n ∈ List.range 256, (encodeByte (UInt8.ofNat n)).all (fun c => c.toNat < 128) = true := by
  decide

/-- The digit lookup carries a fallback it cannot reach. Reaching it would emit a character that is
not hex, and a signature built from one is rejected with no indication of where it went wrong. -/
theorem encodeByte_ne_fallback :
    ∀ n ∈ List.range 256, (encodeByte (UInt8.ofNat n)).all (fun c => c != '?') = true := by
  decide

/-- However a path is normalised away, what is signed is still an absolute path. A canonical
request whose second line is empty or relative is one AWS will reject, and the rejection names the
signature rather than the path. -/
theorem canonicalUri_absolute (path : String) : (canonicalUri path).startsWith "/" = true := by
  simp [canonicalUri]
  split <;> simp

public def checks : List (String × Bool) :=
  [ ("an empty path is a single slash", canonicalUri "" == "/"),
    ("a root path stays a single slash", canonicalUri "/" == "/"),
    ("a query parameter with an empty value keeps its =",
      canonicalQuery [("b", ""), ("a", "2"), ("a", "1")] == "a=1&a=2&b=") ]

end Tests.Encoding
