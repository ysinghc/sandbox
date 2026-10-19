// SPDX-License-Identifier: GPL-2.0-only
// vsock_peer.h -- #10: which peer may drive the guest control channel.
#ifndef SANDBOX_VSOCK_PEER_H
#define SANDBOX_VSOCK_PEER_H

// The guest agent's listener is reachable by *any* process inside the guest, so
// it must authenticate a connection before acting on it -- otherwise an
// unprivileged guest process could impersonate the host and inject environment
// (and, once exec/file RPC lands, drive the sandbox).
//
// Only the host's vsock proxy legitimately presents the host CID. This is a
// real boundary rather than a formality because the CID is assigned by the
// vsock transport, not by the sender: a guest connect() to CID_HOST is routed
// out to the host, never back into the guest's own listener, so a guest process
// cannot forge it. Anything else -- VMADDR_CID_LOCAL, the guest's own CID, an
// unconnected socket -- is refused.
//
// A per-session token is not usable in this direction: it would have to reach
// the guest over the very channel being authenticated, and a snapshot template
// is built once and restored per session. Guest->host needs no token either:
// each VM has its own vsock UDS, so provenance is already per-VM.
#define VSOCK_PEER_HOST_CID 2u

// Pure predicate, split out so the decision table can be unit tested on a host
// with no VM (tests/test_vsock_peer.c).
int vsock_peer_cid_is_host(unsigned cid);

// 1 iff `fd` is an AF_VSOCK socket whose peer CID is the host's. 0 otherwise,
// including any getpeername() failure.
int vsock_peer_is_host(int fd);

#endif  // SANDBOX_VSOCK_PEER_H
