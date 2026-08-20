/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Aws.Sigv4

/-!
The seam between this library's API and the canonical request, which the published suite does not
reach: it describes raw HTTP requests, and says nothing about what a `Request` value should do with
a header the signer supplies for itself.
-/

namespace Tests.Canonical
open Aws.Sigv4

private def instant : Timestamp := ⟨1440938160⟩

private def plain : Credentials := { accessKeyId := "AKID", secretAccessKey := "secret" }

private def withHeaders (hs : List (String × String)) : List (String × String) :=
  preparedHeaders plain instant
    { method := "GET", path := "/", host := "example.amazonaws.com", headers := hs }

public def checks : List (String × Bool) :=
  [ ("host and the date are always signed", signedHeaders (withHeaders []) == "host;x-amz-date"),
    ("a caller's own Host neither displaces nor duplicates the signer's",
      (withHeaders [("Host", "evil.example.com")]).filter (fun h => h.1 == "host")
        == [("host", "example.amazonaws.com")]),
    ("a caller's own X-Amz-Date does not displace the signer's",
      (withHeaders [("X-Amz-Date", "19700101T000000Z")]).filter (fun h => h.1 == "x-amz-date")
        == [("x-amz-date", "20150830T123600Z")]),
    ("the signed request carries every header the signature commits to",
      let signed := sign plain { region := "eu-west-1", service := "ses" } instant
        { method := "POST", path := "/v2/email/outbound-emails", host := "example.amazonaws.com" }
      signed.headers.map (·.1) == ["x-amz-date", "Authorization"]) ]

end Tests.Canonical
