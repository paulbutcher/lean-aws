/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Aws.Sigv4.Canonical
import Codec.Hex
import Crypto.Hmac
import Crypto.Sha256

/-!
AWS Signature Version 4 request signing.

Signing is a pure total function of a request, a set of credentials, and a timestamp. Nothing here
performs IO, which is what lets a published vector fix the time and check the result.
-/

public section

namespace Aws.Sigv4

def algorithm : String := "AWS4-HMAC-SHA256"

def credentialScope (scope : SigningScope) (t : Timestamp) : String :=
  s!"{t.dateStamp}/{scope.region}/{scope.service}/aws4_request"

def stringToSign (scope : SigningScope) (t : Timestamp) (canonical : String) : String :=
  String.intercalate "\n"
    [ algorithm,
      t.amzDate,
      credentialScope scope t,
      Codec.Hex.encodeString (Crypto.Sha256.hashUtf8 canonical) ]

/-- Each step takes the previous step's raw bytes as its key, which is why the primitive has to
return bytes rather than an encoding of them. -/
def signingKey (secret : String) (scope : SigningScope) (t : Timestamp) : ByteArray :=
  let kDate := Crypto.hmac ("AWS4" ++ secret).toUTF8 t.dateStamp.toUTF8
  let kRegion := Crypto.hmac kDate scope.region.toUTF8
  let kService := Crypto.hmac kRegion scope.service.toUTF8
  Crypto.hmac kService "aws4_request".toUTF8

def signature (secret : String) (scope : SigningScope) (t : Timestamp) (toSign : String) :
    String :=
  Codec.Hex.encodeString (Crypto.hmac (signingKey secret scope t) toSign.toUTF8)

/--
What to send, and what it was computed from. The intermediates are returned because a rejected
signature is otherwise undiagnosable: AWS answers a mismatch with the canonical request it
expected, and comparing that against this one is the whole of the investigation.
-/
structure Signed where
  /-- Send all of these. They are the headers the signature commits to, so a caller who sends
  only `Authorization` sends a header set the signature does not match. -/
  headers : List (String × String)
  canonicalRequest : String
  stringToSign : String
  signature : String
  deriving Repr

def authorization (creds : Credentials) (scope : SigningScope) (t : Timestamp)
    (hs : List (String × String)) (sig : String) : String :=
  s!"{algorithm} Credential={creds.accessKeyId}/{credentialScope scope t}, " ++
    s!"SignedHeaders={signedHeaders hs}, Signature={sig}"

def sign (creds : Credentials) (scope : SigningScope) (t : Timestamp) (r : Request) : Signed :=
  let hs := preparedHeaders creds t r
  let canonical := canonicalRequest r hs
  let toSign := stringToSign scope t canonical
  let sig := signature creds.secretAccessKey scope t toSign
  { headers :=
      hs.filter (fun h => h.1 != "host") ++ [("Authorization", authorization creds scope t hs sig)]
    canonicalRequest := canonical
    stringToSign := toSign
    signature := sig }

end Aws.Sigv4
