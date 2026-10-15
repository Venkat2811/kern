# Kimi-K3 reproduction on HGX B300

This branch preserves the runtime changes exercised on eight-GPU HGX B300
nodes on 2026-10-15. Its base is the deployment's pinned kern revision
`3eeec9044ba437e2818052a17895b8670a552cee`. The fork's `master` separately
tracks upstream; the experimental branch is not a rebase onto a newer runtime.

The corresponding model/kernel branch is
[Venkat2811/kern-k3-pp-prefill](https://github.com/Venkat2811/kern-k3-pp-prefill/tree/codex/b300-reproduction-2026-10-15).
Its [B300 guide](https://github.com/Venkat2811/kern-k3-pp-prefill/blob/codex/b300-reproduction-2026-10-15/b300/README.md)
contains the required launch-grid adaptations and the optional KDA experiment.

## Runtime changes

### Same-host POSIX allocation sharing

The tested devices advertise CUDA Fabric-handle support, but creating a Fabric
allocation in the tested container returns `CUDA_ERROR_NOT_PERMITTED` without
an IMEX channel. Set `KERN_LOCAL_IPC_DIR` to select POSIX-FD VMM handles instead.
All communicating processes must see the same absolute private directory on
the same Linux host and run as the same UID:

```sh
install -d -m 700 /tmp/kern-local-ipc
export KERN_LOCAL_IPC_DIR=/tmp/kern-local-ipc
```

The existing 72-byte peer envelope carries a tagged broker locator. A Unix
socket transfers the FD with `SCM_RIGHTS`; the implementation checks the host
boot ID, peer UID, directory ownership and permissions. Export registrations
live with their allocation owners, received FDs close after CUDA import, and
FDs are close-on-exec. With the variable absent, the original Fabric/default
allocation behavior is unchanged. Model arithmetic is unchanged.

This is **same-host sharing only**. It does not make PP8-to-decode transfers
work across separate HGX nodes. The original direct peer mapping still needs
a separate pack/transfer/scatter/completion protocol over IB for that topology.

### Preserve the first prefill token's stop cause

The PP head already emits the actual selected token. It now preserves the
typed result of `StopPolicy::classify` when emitting `Note::Finish`.
Previously, discarding that cause activated the pinned frontend's legacy
compatibility-EOS path: a request with `max_tokens=1` could report two output
tokens when its one selected token was EOS. The change preserves ordinary
length completion and explicit-stop semantics and adds no model step.

## Build and validation

Build on Linux with the repository's locked dependencies, Rust/cargo 1.98.1,
`protoc`, OpenSSL development files, and the runtime libraries described in
the main serving documentation:

```sh
cargo build --locked --release -p kern-run -p kern-serve
cargo test --locked --release -p kern-runtime local_ipc::tests -- --test-threads=1
```

The two local-IPC tests exercise FD duplication/closure/close-on-exec and
foreign-host rejection before connecting. Those tests do not create a CUDA
context. The numerical and multi-process checks below were performed during
the B300 experiment; they are not replaced by these two CPU tests.

- Fresh-process POSIX export/import, peer read/write, page/slot/dealt-row and
  remapped-state checks passed.
- Eight-process all-to-all and mapped peer all-reduce checks passed eagerly
  and under CUDA graphs with the B300 manifest grids.
- Full 93-layer PP8 serving and TP8/EP8/DCP8 standalone decode ran.
- All eight tests in the pinned frontend's stepped bridge passed in an
  isolated dependency checkout, including an added ordinary-length / EOS /
  explicit-stop regression. The real EOS HTTP case then reported one output
  token. The dependency was not changed in the serving build.

The four modified runtime/server source files are byte-identical to the
preserved tested source. The resulting experiment's serving executable SHA256
was `d254976477ef7c867d212ba95bb980b7b6dd591a11937276b1ac3c89036b8832`;
rebuilding in another environment need not yield that executable hash.

## Results and limits

On a cold, one-output-token, 2K–32K-input diagnostic, the highest tested
passing nominal rates were 1.75 requests/s for kern and 1.5 for the tested
SGLang recipe. At identical 1.75 traffic, p90 TTFT was 3.778 versus 8.142
seconds, against a 5-second diagnostic gate. This is a whole-stack comparison
with different parallelism, chunking and KV/state precision, not a precise
maximum-capacity estimate or the published end-to-end AgentX result.

Full cross-node 1P2D AgentX serving is **not reproduced by this branch**.
GPU RDMA connectivity was demonstrated separately, but model-state handoff
integration remains missing. Broad quality equivalence and a 50–100% system
throughput gain have not been established.
