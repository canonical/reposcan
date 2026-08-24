# Use a published image

The container backends run scans in a single tool image that holds every pinned
tool. By default, reposcan pulls a published, digest-pinned image from GHCR on
first use and reuses it afterward. You can also build the image locally or pull
a different one.

## Run the default published image

With no `image` set, reposcan pulls the canonical published image, pinned by
digest so its content is verified on every pull:

```
reposcan sbom ./repo             # pulls the default image on first use
```

The `canonical` shorthand names the same image explicitly:

```
reposcan --image canonical sbom ./repo
```

The LXD backend always builds locally.

## Pull a different image

reposcan can run from any remote OCI image with the `image` config key:

```
reposcan config set image ghcr.io/canonical/repo-scanner:latest
reposcan config set image ghcr.io/canonical/repo-scanner@sha256:...
```

reposcan verifies a pulled image before running it: a digest-pinned reference is
trusted by content, and a tag-only reference is pinned on first use and refused
later if the tag has moved to different content. Clear the key to go back to the
default pull:

```
reposcan config unset image
```

## Build the image locally

Pass `--image build` to build the tool image locally instead:

```
reposcan --image build sbom ./repo           # build, then inventory
reposcan config set image build              # persisted
```

Build (or rebuild) the tool image without running a scan:

```
reposcan image build
reposcan image build --backend docker
```

The image is content-addressed by a digest of its build script, so reposcan
reuses an existing image when nothing has changed and rebuilds when a tool
version, hash, or the base image changes.

## Manage the image record

reposcan records the identity of each image it built or pulled. Inspect or clear
that record:

```
reposcan image cache list
reposcan image cache remove <reference>
reposcan image cache clear
```

`image cache remove` clears a stale entry.
