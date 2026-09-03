/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import AwsCredentials.Cache
public import AwsCredentials.Container
public import AwsCredentials.Environment

/-!
Resolving AWS credentials, which is IO and so is not in `Aws.Sigv4`.

The environment and the container endpoint are the two sources, in that order. EC2 instance
metadata, the shared config and credentials files, SSO and role assumption are not here; between
them the two that are cover deploying to ECS and to Fargate.

A container endpoint's credentials expire and are replaced, so a long-running process holds
`system`, or its own composition ending in `Provider.cached`. Credentials resolved once are
credentials that stop working at the first rotation, which looks like a healthy deployment for
several hours first.
-/

public section

namespace Aws.Credentials

/-- The environment, then the container endpoint, cached. -/
def system : IO (Provider IO) :=
  Provider.cached systemClock (Provider.chain [environment ioEnv, container ioEnv curlHttp])

end Aws.Credentials
