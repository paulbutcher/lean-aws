# Changelog

## [0.4.1] - 2026-11-24

* On leancrypto 0.5.0 and leancurl 0.4.0

## [0.4.0] - 2026-11-24

* Breaking: requires Lean v4.36.0; move to that toolchain
* On json 0.4.0 and leancurl 0.3.3

## [0.3.2] - 2026-10-20

Chore: bump dependencies

## [0.3.1] - 2026-09-09

On leancrypto 0.4.0.

## [0.3.0] - 2026-09-02

* A `credentials` subpackage, which resolves credentials from the environment and from the container endpoint an ECS or Fargate task role arrives through, and refreshes temporary ones before they expire

## [0.2.1] - 2026-08-29

* Proofs that a canonical URI is always absolute, and that percent-encoding never emits the fallback character its digit lookup carries
* The README gained usage and verification sections, and the project now keeps a changelog

## [0.2.0] - 2026-08-20

Switch to module system, on leancrypto 0.3.0.

## [0.1.0] - 2026-08-18

Initial release: AWS Signature Version 4 request signing, extracted from lean-authentication.
