/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Lake
open Lake DSL

require leanaws from ".."

require leancurl from git
  "https://github.com/paulbutcher/leancurl" @ "v0.3.1"

require json from git
  "https://github.com/paulbutcher/lean-json" @ "v0.3.0"

/-- Resolution talks to the container endpoint, so this package has an HTTP client and a JSON
parser and the package it requires has neither. -/
package leanawsCredentials where
  version := v!"0.3.0"
  leanOptions := #[
    ⟨`autoImplicit, false⟩,
    ⟨`relaxedAutoImplicit, false⟩,
    ⟨`warningAsError, true⟩]

@[default_target]
lean_lib AwsCredentials

@[test_driver]
script tests (args) do
  let pkg ← getRootPackage
  let child ← IO.Process.spawn {
    cmd := "lake"
    args := #["test", "--"] ++ args.toArray
    cwd := pkg.dir / "test"
  }
  child.wait
