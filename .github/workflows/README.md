### Github Actions Workflow

This build file replaces the existing `Jenkins.ci` build process.

`lint.yaml` replaces the `Static code validation` stage of the Jenkins build.

`build.yaml` replaces the `Build / Test` stage of the Jenkins build.

Many of the other stages are replaced merely by the fact we're using Github Actions, we use prebuild Docker containers so we don't have to replicate the steps for building containers.

The `Build result notification` stage was not moved to GHA, build failures will be reports via GHA.

The build process for `Jenkins.nightly` was not ported to GHA.