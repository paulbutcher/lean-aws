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

/-- An unreserved byte is passed through as itself, rather than as an escape which happens to
decode to it. What is signed is the encoded form, so a byte escaped where the specification says it
should not be is a mismatch naming no byte in particular.

`isUnreserved b` answers `true` to exactly the RFC 3986 unreserved bytes, and of those the encoder
returns the one character whose codepoint is the byte. All 66 of them are ASCII, so reading the
byte as a codepoint is the identity the specification asks for, and the hypothesis holds of those
66 rather than of none. -/
theorem encodeByte_unreserved (b : UInt8) (h : isUnreserved b = true) :
    encodeByte b = [Char.ofNat b.toNat] := by
  simp [encodeByte, h]

/-- Every other byte becomes an escape of exactly three characters, so no byte can widen or narrow
the encoding of the byte beside it, and none can disappear from what is signed.

The hypothesis selects the 190 bytes the theorem above excludes, and of those the encoder returns
`%` and two digits, one triple per byte however large the byte. Only the width is claimed; that the
two digits are the byte in hex is left to the published vectors. -/
theorem length_encodeByte_reserved (b : UInt8) (h : isUnreserved b = false) :
    (encodeByte b).length = 3 := by
  simp [encodeByte, h]

set_option maxRecDepth 8000

/-- Nothing the encoder emits needs encoding itself, which is what makes a second pass over an
already-encoded path well defined rather than a pass over arbitrary bytes.

`List.range 256` is every `UInt8`, `UInt8.ofNat` being the identity below 256, and `List.all`
answers `true` only where every character emitted for that byte is below codepoint 128. It is not
answering `true` to an empty output: the theorems above give the output length 1 or 3 for every
byte. -/
theorem encodeByte_ascii :
    ∀ n ∈ List.range 256, (encodeByte (UInt8.ofNat n)).all (fun c => c.toNat < 128) = true := by
  decide

/-- The digit lookup carries a fallback it cannot reach. Reaching it would emit a character that is
not hex, and a signature built from one is rejected with no indication of where it went wrong.

`hexDigits.getD` answers `'?'` exactly where the index is past the end, so no `'?'` in the output
of any of the 256 bytes is the index never being past it. The character cannot arrive by the other
branch either, `'?'` being one of the bytes that escape. -/
theorem encodeByte_ne_fallback :
    ∀ n ∈ List.range 256, (encodeByte (UInt8.ofNat n)).all (fun c => c != '?') = true := by
  decide

/-- However a path is normalised away, what is signed is still an absolute path. A canonical
request whose second line is empty or relative is one AWS will reject, and the rejection names the
signature rather than the path.

`startsWith "/"` answers `true` to any string whose first character is a slash, and the claim is of
every `path`, normalised away to nothing or not: one branch returns `"/"` itself and the other
writes a slash before the first segment. -/
theorem canonicalUri_absolute (path : String) : (canonicalUri path).startsWith "/" = true := by
  simp [canonicalUri]
  split <;> simp

public def checks : List (String × Bool) :=
  [ ("an empty path is a single slash", canonicalUri "" == "/"),
    ("a root path stays a single slash", canonicalUri "/" == "/"),
    ("a query parameter with an empty value keeps its =",
      canonicalQuery [("b", ""), ("a", "2"), ("a", "1")] == "a=1&a=2&b=") ]

end Tests.Encoding
