/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Aws.Sigv4.Credentials
import Aws.Sigv4.Encoding
import Aws.Sigv4.Time
import Codec.Hex
import Crypto.Sha256

namespace Aws.Sigv4

/--
An HTTP request described as data. `host` is a field of its own rather than one of `headers`
because SigV4 requires it signed, and a caller who forgets it should get a signature rather than
a mismatch to debug.
-/
structure Request where
  method : String
  path : String
  host : String
  query : List (String × String) := []
  headers : List (String × String) := []
  body : ByteArray := ⟨#[]⟩

private def collapseSpaces : List Char → List Char
  | [] => []
  | ' ' :: ' ' :: rest => collapseSpaces (' ' :: rest)
  | c :: rest => c :: collapseSpaces rest
  termination_by cs => cs.length

/-- Values are trimmed and their internal runs of spaces collapsed to one. A value inside a quoted
string is left to the same treatment, which the specification exempts and no header this signs
uses. -/
private def trimCollapse (v : String) : String :=
  let cs := v.toList
  let trimmed := ((cs.dropWhile Char.isWhitespace).reverse.dropWhile Char.isWhitespace).reverse
  String.ofList (collapseSpaces trimmed)

/-- Inserts before an equal name rather than after, so that two headers of the same name keep the
order they were supplied in and the comma-joined value is the one the caller intended. -/
private def insertHeader (h : String × String) :
    List (String × String) → List (String × String)
  | [] => [h]
  | k :: rest => if h.1 ≤ k.1 then h :: k :: rest else k :: insertHeader h rest

private def sortHeaders : List (String × String) → List (String × String)
  | [] => []
  | h :: rest => insertHeader h (sortHeaders rest)

private def mergeSameName : List (String × String) → List (String × String)
  | [] => []
  | [h] => [h]
  | h :: k :: rest =>
    if h.1 == k.1 then mergeSameName ((h.1, h.2 ++ "," ++ k.2) :: rest)
    else h :: mergeSameName (k :: rest)
  termination_by hs => hs.length

/-- Supplied by the signer, so a caller's own copy is dropped rather than comma-joined onto ours. -/
private def signerOwned : List String := ["host", "x-amz-date", "x-amz-security-token"]

/--
The headers the signature covers: lowercased, whitespace-normalised, sorted by name, and with
same-named headers joined. `host` and `x-amz-date` are always among them, and
`x-amz-security-token` whenever the credentials carry one.
-/
def preparedHeaders (creds : Credentials) (t : Timestamp) (r : Request) :
    List (String × String) :=
  let supplied := (r.headers.map fun (n, v) => (n.toLower, trimCollapse v)).filter
    fun h => !signerOwned.contains h.1
  let owned :=
    ("host", trimCollapse r.host) :: ("x-amz-date", t.amzDate) ::
      (match creds.sessionToken with
       | some token => [("x-amz-security-token", trimCollapse token)]
       | none => [])
  mergeSameName (sortHeaders (supplied ++ owned))

/-- Derived from the prepared list rather than assembled separately, so it cannot name a header the
canonical block does not carry, or order them differently. -/
def signedHeaders (hs : List (String × String)) : String :=
  String.intercalate ";" (hs.map (·.1))

/-- An empty body hashes as SHA-256 of the empty string, which needs no special case: it is not an
empty hash and it is not `UNSIGNED-PAYLOAD`. -/
def payloadHash (body : ByteArray) : String :=
  Codec.Hex.encodeString (Crypto.Sha256.hash body)

def canonicalRequest (r : Request) (hs : List (String × String)) : String :=
  String.intercalate "\n"
    [ r.method.toUpper,
      canonicalUri r.path,
      canonicalQuery r.query,
      String.join (hs.map fun (n, v) => n ++ ":" ++ v ++ "\n"),
      signedHeaders hs,
      payloadHash r.body ]

end Aws.Sigv4
