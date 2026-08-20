/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Aws.Sigv4
import Codec.Hex
import Crypto.Sha256

/-!
The published worked examples. These are examples rather than theorems deliberately: the claim
being checked is agreement with a constant AWS published, which no proof about this code could
establish.

Each is checked at every intermediate stage and not at the final signature alone. A mismatch in
the signature says only that something is wrong; a mismatch in the canonical request says where,
and the canonical request and string to sign are text, so they can be read rather than trusted.
-/

namespace Tests.Vectors
open Aws.Sigv4

/-- 2015-08-30T12:36:00Z, the instant every published example uses. Given as epoch seconds because
that is what `Timestamp` holds; the first check below is that it renders as the example says. -/
private def instant : Timestamp := ⟨1440938160⟩

private def exampleSecret : String := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

private def credentials : Credentials :=
  { accessKeyId := "AKIDEXAMPLE", secretAccessKey := exampleSecret }

private def scope : SigningScope := { region := "us-east-1", service := "service" }

private def vanilla : Request :=
  { method := "GET", path := "/", host := "example.amazonaws.com" }

private def vanillaSigned : Signed := sign credentials scope instant vanilla

private def expectedCanonical : String :=
  String.intercalate "\n"
    [ "GET",
      "/",
      "",
      "host:example.amazonaws.com",
      "x-amz-date:20150830T123600Z",
      "",
      "host;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]

private def expectedStringToSign : String :=
  String.intercalate "\n"
    [ "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      Codec.Hex.encodeString (Crypto.Sha256.hashUtf8 expectedCanonical) ]

public def checks : List (String × Bool) :=
  [ -- If the civil-date arithmetic is wrong, everything below it fails for a reason that has
    -- nothing to do with signing, so it is checked first.
    ("the example instant renders as the examples say",
      instant.amzDate == "20150830T123600Z" && instant.dateStamp == "20150830"),
    ("get-vanilla canonical request",
      vanillaSigned.canonicalRequest == expectedCanonical),
    ("get-vanilla string to sign",
      vanillaSigned.stringToSign == expectedStringToSign),
    ("get-vanilla signature",
      vanillaSigned.signature ==
        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"),
    ("get-vanilla authorization header",
      vanillaSigned.headers.any fun (name, value) =>
        name == "Authorization" &&
          value == "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/" ++
            "aws4_request, SignedHeaders=host;x-amz-date, Signature=" ++
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"),
    -- The documented signing key derivation, which publishes the final key of the chain. When the
    -- chain is wrong, the step it went wrong at is otherwise unrecoverable from the output.
    ("signing key derivation",
      Codec.Hex.encodeString
          (signingKey exampleSecret { region := "us-east-1", service := "iam" } instant) ==
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9") ]

end Tests.Vectors
