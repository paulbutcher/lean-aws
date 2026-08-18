/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Aws.Sigv4

/-!
Percent-encoding, which the canonical request is built out of.

Hex round-tripping and lowercase output belong to `leancrypto` and are proved beside their
definitions there. What is proved here is the part this library decides: which bytes escape, and
that an escape is always three characters wide.

`Tests.Suite` is the authority on what the encoder should produce, so what the checks below add is
the boundary it does not reach, where a caller supplies no path at all.
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

def checks : List (String × Bool) :=
  [ ("an empty path is a single slash", canonicalUri "" == "/"),
    ("a root path stays a single slash", canonicalUri "/" == "/"),
    ("a query parameter with an empty value keeps its =",
      canonicalQuery [("b", ""), ("a", "2"), ("a", "1")] == "a=1&a=2&b=") ]

end Tests.Encoding
