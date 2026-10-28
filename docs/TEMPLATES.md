# Templates

A **template** is the captured state every sandbox starts from: a booted guest
(memory + device state), the root filesystem it booted, the kernel, and the base
image each session's `/workspace` is cloned from. Sessions are restored from a
template, never booted, which is how a sandbox is provisioned in tens of
milliseconds.

The root filesystem is read-only and the same for every session. So "I need a
library" has three answers, in this order of preference:

| You need… | Do this | Survives | Cost |
|---|---|---|---|
| a library the image already has | nothing (`python3`, `curl`, `git` …: see the spec's `packages`) | always | none |
| a Python/Node/… package for one agent or conversation | install it into `/workspace` (`pip install --target /workspace/.pylib …`, `npm --prefix /workspace …`) over the session's egress policy | the session (persistent volume) | per session, network |
| a library every sandbox of a kind should have | **extend the template**: add it to the spec and rebuild | every session of that template | one build |

`apt-get install` inside a running sandbox does not work and is not a workflow:
`/` is mounted read-only, and anything written there would not persist.

## Build a template

A template is built from a spec checked into `templates/<name>/`:

```
templates/python-agent/
  template.conf     # what to build
  provision.sh      # optional: extra build steps
```

```sh
sudo bash scripts/build-template.sh templates/python-agent
```

That runs, in order: `debootstrap` the suite → install `packages` → run
`provision.sh` in the new root → write a deterministic ext4 image → cold-boot it
until the guest reports ready → snapshot → verify → publish into the store. The
build is staged as `.build-<name>`; the template being served is not touched until
the new one is complete, then the name is repointed in one atomic step.

It needs root (debootstrap, `/dev/kvm`), `debootstrap`, `e2fsprogs`, and a guest
kernel (`--kernel`, `$SANDBOX_KERNEL`, or `/opt/sandbox-assets/vmlinux`). The
snapshot root is `$SANDBOX_SNAPSHOT_ROOT` (default
`/var/lib/sandbox-engine/snapshots`). Check a spec without building anything or
being root: `bash scripts/build-template.sh templates/NAME --check`.

### `template.conf`

Plain `key=value` lines, `#` comments. The file is parsed as data (never sourced);
an unknown key or a malformed value is an error.

| Key | Default | Meaning |
|---|---|---|
| `base` | `debian` | Only `debian` is supported. |
| `suite` | `bookworm` | Debian suite. |
| `packages` | *(none)* | Comma-separated packages added to the base image. |
| `snapshot` | *(live mirror)* | A `snapshot.debian.org` timestamp such as `20261001T000000Z`: install the packages as the archive was at that moment. |
| `provision` | *(none)* | A script in the spec directory, run as root inside the new image after the packages. |
| `memory_mib` | `256` | Memory of the captured VM. |
| `vcpus` | `1` | vCPUs of the captured VM. |
| `workspace_size_mb` | `512` | Size of every session's `/workspace` volume (a property of the template, because the image is pre-formatted and cloned). |
| `description` | | Free text. |

`provision.sh` runs with the host's network (it is a build, not a sandbox) and a
clean environment. Keep it deterministic: pin versions, do not download "latest",
do not write the date or random values.

### Add a library to a template

1. Add the package to `packages=` (or install it in `provision.sh`).
2. `sudo bash scripts/build-template.sh templates/<name>`.
3. `sandbox-cli template list` shows the new digest under the name. New sandboxes
   use it; running ones are unaffected.
4. Something wrong? `sandbox-cli template rollback --name <name>`.

## Identity: digests and the store

```
<snapshot root>/
  .store/<digest>/          the template: memory.snap, vmstate, rootfs.ext4,
                            base_workspace.ext4, vmlinux, manifest.bin, template.json
  .store/history/<name>     append-only log of what each name pointed at
  <name>  ->  .store/<digest>
```

The **digest** is the SHA-256 of the hashes and sizes of the payloads: memory,
vmstate, rootfs, workspace base and kernel. Two templates are the same template
exactly when their payloads are. `template.json` (name, build time, spec and kernel
digests, sizes) is metadata and is not part of the identity.

- **Immutable.** A published directory is never modified; it is made read-only,
  and `sandbox-cli template verify --name <name|digest>` re-hashes every payload and
  checks the directory really holds the digest it is filed under.
- **Content-addressed.** Publishing content that is already stored does not store
  it again.
- **Atomic.** The name the daemon opens is a symlink. Publish and rollback
  repoint it with one `rename(2)`, so a concurrent restore sees the old template or
  the new one, never neither.
- **Versioned.** `manifest.bin` carries a version the daemon compares to notice a
  changed template (it drains its warm pool when it differs). It is derived from the
  digest, so the same template always has the same version, a different one a
  different version, and a rollback restores the old one. It is *not* a build counter.
- **Adopting old templates.** A real directory already at `<name>` (a template
  built before the store existed) is moved into the store the first time a new
  template is published under that name, and can be rolled back to.

### What is and is not reproducible

The **image is**: with the same revision, spec and package set, two builds produce
a byte-identical `rootfs.ext4` (a fixed filesystem UUID and hash seed, timestamps
clamped to `SOURCE_DATE_EPOCH` — by default the commit time — and the install-date
and cache files that vary removed). The privileged CI job builds the image twice and
fails if the bytes differ. For this to hold across days, set `snapshot=`: with the live
mirror the package set itself changes when Debian publishes an update. It is verified
on one builder; a different host's filesystem may order directory entries differently.

The **snapshot is not** bit-reproducible: it is the memory of a booted guest, and
two boots differ in timing-derived state. So two builds of one spec give two
digests. That is by design — a digest names *this* captured template — and the
`spec_sha256`, `kernel_sha256` and `rootfs_sha256` in `template.json` are what tie
it to its inputs.

Files a template captures in memory (and in the page cache) are the same in every
session restored from it. Do not put secrets in a template; see
[THREAT_MODEL.md](THREAT_MODEL.md).

## Operate the store

```sh
sandbox-cli template list                       # names with digests, then unreferenced entries
sandbox-cli template verify --name python-agent # or a digest
sandbox-cli template rollback --name python-agent
sandbox-cli template unpublish --name old-thing # withdraw a name
sandbox-cli template gc                         # report what could be removed
sandbox-cli template gc --apply                 # remove it
```

`publish` (moving an already-built, staged directory into the store) is what
`build` does at its end; it is exposed for tooling that builds elsewhere.

### Garbage collection

`gc` removes store entries that nothing needs. An entry is needed when

- a name currently points at it, **or**
- it is among the last `--keep` distinct versions a name has pointed at (default
  **2**: the current one and the one to roll back to; use `--keep 1` to keep only
  the current one).

It also never removes an entry younger than `--min-age` seconds (default **86400**),
a grace period for anything still in flight. It reports one line per entry saying what
it kept and why, or removed and how many bytes that frees, and **does nothing unless
`--apply` is given**. Unpublishing a name releases its entries.

A running sandbox is not affected by removing its template's files: the VM and its
memory handler hold them open, and an unlinked file lives until they exit.

## Per-architecture templates

A template is built on a host of its own architecture (the guest agent is compiled
for it, and the snapshot is only valid on the CPU family that took it). The spec is
architecture-neutral, so one revision builds an x86_64 and an aarch64 template by
running `build-template.sh` on each. The x86_64 pipeline is what CI exercises today;
the aarch64 leg is deferred with the rest of the ARM milestone.
