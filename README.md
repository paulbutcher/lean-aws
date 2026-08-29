# lean-aws

AWS Signature Version 4 request signing for Lean 4.

## What is checked

AWS's published SigV4 test suite, 31 cases committed rather than fetched, each checked at all three stages: canonical request, string to sign, and `Authorization` header. Alongside it run the worked examples from the signing documentation, including the published signing key derivation, and the civil-date arithmetic at the instants where a wrong calendar shows.

Claims that hold for every input are proved rather than sampled: that percent-encoding emits only ASCII and never the fallback its digit lookup carries, and that each field of a date stamp and a timestamp is the width the format requires. A date of seven characters is rejected as firmly as the wrong date, and neither reports where it went wrong.

## Building

```
lake build
lake test
```
