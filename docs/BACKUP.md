# Sandbox Engine — Backup & Restore

## 1. What to back up

| Item | Path (default) | Why | Recoverable without a backup? |
|---|---|---|---|
| Templates + manifests | `/var/lib/sandbox-engine/snapshots/` | Expensive to rebuild; integrity-checked | Yes, but slow + needs guest assets |
| Session workspaces | `/var/lib/sandbox-engine/workspaces/` | User session volumes (**unrecoverable** if lost) | No — back them up or accept the loss |
| Engine config | `/var/lib/sandbox-engine/config/engine.conf` | Tuned limits, allowlists | Defaults only |
| Broker credentials | `/etc/sandbox-engine/credentials.conf` (0600) | **Secret** upstream keys | Only from the upstream provider |
| systemd units | `/etc/systemd/system/sandboxd.service`, `.../sandbox-privileged.service` | Local overrides for both halves (mutual `BindsTo=`) | Reinstall + re-apply overrides |

The helper keeps only an in-memory child table: no backup needed for it, but
live VMs still die with it (crash-orphaning semantics are unchanged by #9).
Reinstall prerequisites (daemon user, directory owners, the userfaultfd knob)
ship as `packaging/{sysusers.d,tmpfiles.d,sysctl.d}/sandbox-engine.conf`.

Do **not** back up/restore:

- `/var/lib/sandbox-engine/jail/**` — per-boot jail scratch (mounts, device
  nodes); recreated per VM.
- `/var/run/sandbox-engine/**` — sockets; recreated by the daemon.
- `/run/sandbox-privileged/**` — helper socket; recreated by
  `sandbox-privileged.service`.
- `/sys/fs/cgroup/sandboxd/**` — kernel state; recreated at start.
- Live VMs — they do not survive a daemon restart (a `Create` is not a
  checkpoint of running client state).

## 2. Backing up

Templates are written with **atomic rename** (write `*.tmp`, then rename), so a
copy while the daemon is running is consistent at the file level. Still, for a
clean point-in-time set, quiesce the daemon:

```sh
sudo systemctl stop sandboxd.service
# This also stops sandbox-privileged.service via the mutual BindsTo=; both
# must be down before copying state.
systemctl is-active --quiet sandbox-privileged.service && exit 1

sudo install -d -m 0700 /var/backups/sandbox-engine
STAMP=$(date +%Y%m%d-%H%M%S)
sudo tar -C /var/lib/sandbox-engine -czf /var/backups/sandbox-engine/state-$STAMP.tgz \
    snapshots config/engine.conf workspaces

# Credentials are secrets: back them up separately, encrypted, 0600.
sudo tar -C /etc -czf /var/backups/sandbox-engine/creds-$STAMP.tgz sandbox-engine
sudo chmod 600 /var/backups/sandbox-engine/creds-$STAMP.tgz
gpg --encrypt --recipient ops@example.com \
    /var/backups/sandbox-engine/creds-$STAMP.tgz   # recommended

sudo systemctl start sandboxd.service
```

Record the engine version alongside the backup:
`sandboxd --version > /var/backups/sandbox-engine/state-$STAMP.version`.

> Snapshot size: templates are hundreds of MB to a few GB each. Prefer
> filesystem snapshots / object storage over ad-hoc tarballs for the
> `snapshots/` tree.

## 3. Restoring

```sh
sudo systemctl stop sandboxd.service   # also stops sandbox-privileged (BindsTo=)
systemctl is-active --quiet sandbox-privileged.service && exit 1
sudo pkill -9 -x firecracker 2>/dev/null || true

# Engine state (templates + config + session workspaces), with per-writer
# owners: the daemon runs as sandboxd and must write workspaces.
sudo tar -C /var/lib/sandbox-engine -xzf /var/backups/sandbox-engine/state-$STAMP.tgz
sudo chown -R root:root /var/lib/sandbox-engine/snapshots
sudo chown -R sandboxd:sandboxd /var/lib/sandbox-engine/workspaces
sudo chown root:root /var/lib/sandbox-engine/jail   # helper-owned; empty here

# Credentials (decrypt first if encrypted)
gpg --decrypt ... | sudo tar -C /etc -xzf -
sudo chmod 600 /etc/sandbox-engine/credentials.conf
sudo chown root:root /etc/sandbox-engine/credentials.conf

# Verify integrity before trusting the templates
sandboxd --config /var/lib/sandbox-engine/config/engine.conf --validate-config
sandbox-cli verify --template /var/lib/sandbox-engine/snapshots/python-agent

sudo systemctl start sandboxd.service
curl -sf http://127.0.0.1:9180/ready && echo READY
```

### Version mismatch
A backup made with a **different engine version** may carry templates whose
manifest the current engine rejects (`header_size` guard, §10.10). If
`sandbox-cli verify` fails or the daemon refuses to restore, either:

- restore the engine version that produced the backup, or
- rebuild the templates with the current engine.

## 4. Integrity & secrets

- **Integrity:** every template manifest stores SHA-256 digests of `memory.snap`
  and `vmstate`. Restore/`verify` recompute them; a mismatch (corruption, or a
  tampered backup) is refused unless `SANDBOX_VERIFY_SNAPSHOT=0` (do not set
  that in production).
- **Secrets:** `credentials.conf` holds live upstream credentials. Keep it
  `0600 root:root`, never commit it, and encrypt backups. The engine daemon
  never reads it — only the broker does.
- **Immutability:** keep the `snapshots/` directory writable only by root; the
  threat model assumes an attacker cannot replace snapshot files (see
  `SYSTEM DESIGN.md` §12). It must also stay world-readable: the unprivileged
  daemon restores from it as `sandboxd`.

## 5. Recommended cadence

| Cadence | Action |
|---|---|
| After every template (re)build | Snapshot `snapshots/` via storage snapshot |
| On every config/credential change | Versioned backup of `config/` + encrypted `credentials.conf` |
| Before every upgrade | Full `state-*` + `creds-*` + `--version` record (see `UPGRADE.md`) |
| Monthly | Restore-drill into a staging host and run `sandbox-cli verify` |
