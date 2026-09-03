/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Lake
open Lake DSL

require leanawsCredentials from ".."

package «leanaws-credentials-test» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩,
    ⟨`relaxedAutoImplicit, false⟩,
    ⟨`warningAsError, true⟩]

@[default_target]
lean_lib Tests where
  globs := #[`Tests.*]

@[default_target, test_driver]
lean_exe tests where
  root := `Tests.Main
