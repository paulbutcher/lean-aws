# lean-aws

AWS Signature Version 4 request signing for Lean 4.

Signing is a pure total function of a request, a set of credentials, and a timestamp. Nothing here performs IO: resolving credentials, reading the clock, and sending the request are all the caller's, which is what lets a published vector fix the time and check the result.

Header signing, for the services that sign the normalised path. S3 signs the path as given and is out of scope; presigned query-string URLs are not implemented.

## Usage

```lean
import Aws

open Aws.Sigv4

def credentials : Credentials :=
  { accessKeyId := "AKIDEXAMPLE"
    secretAccessKey := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" }

def request : Request :=
  { method := "POST"
    path := "/v2/email/outbound-emails"
    host := "email.us-east-1.amazonaws.com"
    headers := [("Content-Type", "application/json")]
    body := "{\"FromEmailAddress\":\"nobody@example.com\"}".toUTF8 }

def signed : Signed :=
  sign credentials { region := "us-east-1", service := "ses" } ⟨1440938160⟩ request

def main : IO Unit := do
  for (name, value) in signed.headers do
    IO.println s!"{name}: {value}"
```

prints:

```
content-type: application/json
x-amz-date: 20150830T123600Z
Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/ses/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=c92dd4b2ad4c997c47715abfe98e7d7bd356fe12ab8c1d9c901d764920b570bc
```

Send all of them. They are the headers the signature commits to, so a caller who sends only `Authorization` sends a header set the signature does not match. `Host` is absent because an HTTP client sets it for itself, but it is signed, from the `host` field of the `Request`.

The timestamp is seconds since the Unix epoch, and the caller reads the clock:

```lean
import Std.Time

def clock : IO Timestamp := do
  let now ← Std.Time.Timestamp.now
  return ⟨now.toSecondsSinceUnixEpoch.toInt.toNat⟩
```

For credentials from an assumed role, set `sessionToken`. It travels as `X-Amz-Security-Token` and is signed; omitting it from the signed set is accepted by some services and rejected by others, which makes it a defect that surfaces only after a deployment moves to temporary credentials.

```lean
def temporary (token : String) : Credentials :=
  { credentials with sessionToken := some token }
```

A rejected signature is diagnosed from the intermediates `Signed` carries. AWS answers a mismatch with the canonical request it expected, and `signed.canonicalRequest` and `signed.stringToSign` are text rather than a digest, so comparing the two is the whole of the investigation:

```lean
#eval IO.println signed.canonicalRequest
```

```
POST
/v2/email/outbound-emails

content-type:application/json
host:email.us-east-1.amazonaws.com
x-amz-date:20150830T123600Z

content-type;host;x-amz-date
f25fc9beb28330b913e5ee4a5d0418e67716ed60460c1595b9359333f07941b5
```

## Installing

Add to your `lakefile.toml`:

```toml
[[require]]
name = "leanaws"
git = "https://github.com/paulbutcher/lean-aws"
```

## Development

```
lake build   # build the library
lake test    # run the published vectors and the other tests
```

## Formal verification

- Percent-encoding (`test/Tests/Encoding.lean`): an unreserved byte passes through unchanged and every escape is three characters wide; the encoder emits only ASCII, and never the fallback character its hex-digit lookup carries.
- Canonical URI (`test/Tests/Encoding.lean`): however the given path normalises, what is signed is an absolute path.
- Date and time rendering (`test/Tests/Time.lean`): every field of a date stamp and a timestamp is the width the format requires. A date of seven characters is rejected as firmly as the wrong date, and neither says which.

## Published test vectors

- `test/Tests/Suite.lean`: AWS's published SigV4 test suite, 31 cases, each checked at all three stages: canonical request, string to sign, and `Authorization` header. The cases are committed rather than fetched, so the suite fails when this library does and not when a network does.
- `test/Tests/Vectors.lean`: the worked examples from the signing documentation, including the published signing key derivation.

## Other tests

- `test/Tests/Canonical.lean`: the seam between this library's API and the canonical request, which the published suite does not reach, because it describes raw HTTP requests and says nothing about a `Host` or `X-Amz-Date` the caller supplies for itself.
- `test/Tests/Time.lean`: the civil-date arithmetic at the instants where a wrong calendar shows, 2000 and 2100 among them.
- `test/Tests/Encoding.lean`: the boundaries the published suite does not reach, a path with no segments and a parameter with no value.

## License

Apache License 2.0; see [LICENSE](LICENSE).
