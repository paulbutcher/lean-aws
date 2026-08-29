/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public section

namespace Aws.Sigv4

/-- RFC 3986 unreserved. These survive unencoded and nothing else does. -/
@[expose] def isUnreserved (b : UInt8) : Bool :=
  (0x41 ≤ b && b ≤ 0x5A) || (0x61 ≤ b && b ≤ 0x7A) || (0x30 ≤ b && b ≤ 0x39)
    || b == 0x2D || b == 0x5F || b == 0x2E || b == 0x7E

@[expose] def hexDigits : List Char := "0123456789ABCDEF".toList

/-- Uppercase hex, and a space as `%20` rather than `+`. Lowercase digits produce a signature that
differs from AWS's and no useful error. -/
@[expose] def encodeByte (b : UInt8) : List Char :=
  if isUnreserved b then [Char.ofNat b.toNat]
  else ['%', hexDigits.getD (b.toNat / 16) '?', hexDigits.getD (b.toNat % 16) '?']

/-- Encodes the UTF-8 bytes and not the characters, so a multi-byte character becomes one escape
per byte as the specification requires. -/
def uriEncode (s : String) : String := String.ofList (s.toUTF8.toList.flatMap encodeByte)

/--
`path` is the decoded path and is encoded once.

The rule is usually stated as encoding twice, which says the same thing about a path that arrived
already encoded: a caller holding a URL has encoded it once. Taking the decoded form is the version
a caller can supply without having to know which of the two it is holding, and it is the form the
published vectors are written in.
-/
@[expose] def canonicalUri (path : String) : String :=
  let segments := normalise [] (path.splitOn "/")
  if segments.isEmpty then "/"
  else
    "/" ++ String.intercalate "/" (segments.map uriEncode)
      ++ (if path.endsWith "/" then "/" else "")
where
  /--
  Removes dot segments and the empty segments that duplicate slashes leave, so `/example/..`, `/./`
  and `//` all sign as `/`. Every service except S3 signs the normalised path, and S3 is out of
  scope precisely because it does not.
  -/
  normalise : List String → List String → List String
    | acc, [] => acc
    | acc, seg :: rest =>
      if seg == "" || seg == "." then normalise acc rest
      else if seg == ".." then normalise acc.dropLast rest
      else normalise (acc ++ [seg]) rest

/-- Sorted by the encoded bytes rather than the decoded ones. `uriEncode` emits ASCII only, so
codepoint order is byte order here. -/
private def precedes (a b : String × String) : Bool :=
  a.1 < b.1 || (a.1 == b.1 && a.2 < b.2)

private def insertBy (p : String × String) : List (String × String) → List (String × String)
  | [] => [p]
  | q :: rest => if precedes p q then p :: q :: rest else q :: insertBy p rest

def sortPairs : List (String × String) → List (String × String)
  | [] => []
  | p :: rest => insertBy p (sortPairs rest)

/-- Every parameter is written `name=value`, the empty value included. -/
def canonicalQuery (params : List (String × String)) : String :=
  let encoded := params.map fun (k, v) => (uriEncode k, uriEncode v)
  String.intercalate "&" ((sortPairs encoded).map fun (k, v) => k ++ "=" ++ v)

end Aws.Sigv4
