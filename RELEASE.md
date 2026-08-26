# Releasing picobootx

There are two things to release and they are not released together.  The C
library in [src](src) and [include](include) is consumed by `git clone` at a
tag, so its release is a tag and a GitHub release.  The three Rust crates in
[rust](rust) are consumed from crates.io, so their release is a
`cargo publish`.  Each carries its own version and its own changelog.

## The C library

### Update the version

- `PICOBOOTX_VERSION_MAJOR`, `PICOBOOTX_VERSION_MINOR`,
  `PICOBOOTX_VERSION_PATCH` and `PICOBOOTX_VERSION_STRING` in
  [include/picobootx_version.h](include/picobootx_version.h).
- A section for the version in [CHANGELOG.md](CHANGELOG.md), dated.  The
  release workflow reads its release notes from that section and refuses a tag
  the header disagrees with, so both have to be right before the tag is pushed.

### Release

Commit the version updates, then:

```bash
git pull
git push
```

Locally:

```bash
ci/local-checks.sh
```

Then tag and push:

```bash
git tag v<x.y.z>
git push origin v<x.y.z>
```

`.github/workflows/release.yml` runs on a tag matching `v*`.  It builds the
tinyusb example, runs the conformance suite, checks the tag against
`PICOBOOTX_VERSION_STRING`, and creates the GitHub release from the CHANGELOG
section.

## The Rust crates

### Update the versions

- The `version` of each crate that changed, in its own `Cargo.toml`:
  [picobootx](rust/picobootx/Cargo.toml),
  [picobootx-rp2350](rust/picobootx-rp2350/Cargo.toml),
  [picobootx-embassy](rust/picobootx-embassy/Cargo.toml).
- If `picobootx` moved, both dependents move with it, and the requirements in
  `[workspace.dependencies]` in [rust/Cargo.toml](rust/Cargo.toml) move to
  match.  Both put `picobootx`'s own types in their signatures, so a consumer
  holding two versions of `picobootx` gets types that do not unify.
- A section for each version in [rust/CHANGELOG.md](rust/CHANGELOG.md), under
  that crate's heading, dated.

### Release

Commit the version updates, then:

```bash
git pull
git push
```

Locally, the same one command:

```bash
ci/local-checks.sh
```

It is every gate CI applies that this machine can apply too, the coverage gate
among them - which is what catches a source nothing reaches, a floor with no
file behind it, and a file renamed out from under the lists in `ci/`.  The two
it leaves are the picotool and picoboot-rs bridges, which need Linux, vhci-hcd
and root.

Then publish.  One command takes all three, packages and verify-builds each,
and uploads them in dependency order:

```bash
cd rust
cargo publish --dry-run -p picobootx -p picobootx-rp2350 -p picobootx-embassy
cargo publish -p picobootx -p picobootx-rp2350 -p picobootx-embassy
```

Name a subset with fewer `-p` arguments when only some of them moved.  A
version on crates.io is permanent — it can be yanked, never replaced — so the
dry run is not optional.

Then tag what was published, one tag per crate, since three independent
versions have no single number between them:

```bash
git tag picobootx-v<x.y.z>
git tag picobootx-rp2350-v<x.y.z>
git tag picobootx-embassy-v<x.y.z>
git push origin picobootx-v<x.y.z> picobootx-rp2350-v<x.y.z> \
                picobootx-embassy-v<x.y.z>
```

### No GitHub release for the Rust

A GitHub release in this repository is the C library, and the tag names hold
that rather than anyone remembering it.  `release.yml` runs on tags
matching `v*`, and every Rust tag starts with its crate's name, so none of them
reaches it.
