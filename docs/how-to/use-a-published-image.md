# Use a published image

The container backends run scans in a custom image containing every required
scanning tool. By default, reposcan pulls a published, digest-pinned image from
GHCR on first use and reuses it afterward. You can also build the image locally
or pull a different one.

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
reposcan config set image ghcr.io/canonical/reposcan:latest
reposcan config set image ghcr.io/canonical/reposcan@sha256:...
```

reposcan verifies a pulled image before running it: a digest-pinned reference is
trusted by content, and a tag-only reference is pinned on first use and refused
later if the tag has moved to different content. Clear the key to go back to the
default pull:

```
reposcan config unset image
```

## Build the image locally

Pass `--image build` to build the reposcan image locally instead:

```
reposcan --image build sbom ./repo           # build, then inventory
reposcan config set image build              # persisted
```

Build the reposcan image without running a scan. An image already built for the
current spec is reused; `--force` rebuilds it anyway:

```
reposcan image build
reposcan image build --backend docker
reposcan image build --force
```

The image is content-addressed by a digest of its build script, base image, and
install directory, so reposcan reuses an existing image when nothing has changed
and rebuilds when a tool version, hash, or the base image changes.

## Manage the image record

reposcan records the identity of each image it builds, and of each tag-only
image it pulls, as a map of reference to content identity in
`$XDG_DATA_HOME/reposcan/images.json`. A digest-pinned reference needs no
record, since the pull itself verifies its content. To inspect or clear that
record:

```
reposcan image cache list
reposcan image cache remove <reference>
reposcan image cache clear
```

`image cache list` prints each reference with its recorded identity; `image
cache remove` clears a stale entry, and `image cache clear` removes them all.
