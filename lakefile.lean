/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Lake
open System Lake DSL

package leanaws where
  version := v!"0.3.0"
  leanOptions := #[
    ⟨`autoImplicit, false⟩,
    ⟨`relaxedAutoImplicit, false⟩,
    ⟨`warningAsError, true⟩]

require leancrypto from git
  "https://github.com/paulbutcher/leancrypto" @ "v0.3.1"

@[default_target]
lean_lib Aws

/-- The `credentials` subpackage keeps its own tests, which are run here as well so that one
command covers both. It is not required above: resolution needs an HTTP client, and a consumer
that only signs should not resolve one. -/
@[test_driver]
script tests (args) do
  let pkg ← getRootPackage
  let mut code : UInt32 := 0
  for dir in #[pkg.dir / "test", pkg.dir / "credentials" / "test"] do
    let child ← IO.Process.spawn {
      cmd := "lake"
      args := #["test", "--"] ++ args.toArray
      cwd := dir
    }
    let result ← child.wait
    if result != 0 then code := result
  return code
