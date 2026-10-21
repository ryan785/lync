// Phase 5 placeholder — eBPF-based behavioral observation. Not implemented
// in this session; left as a clearly-marked stub so the package boundary
// exists and a follow-up implementer knows where to drop CO-RE BPF objects
// and the libbpf-go (or cilium/ebpf) loader.
//
// Scope when implemented:
//   - Attach BPF programs to tracepoints (sched:sched_process_exec,
//     sched:sched_process_fork, sys_enter_execve, sys_enter_connect, etc.)
//   - Stream events from a perf or ring buffer into Monitor.pending
//   - Find anomalous behavior: shells spawned from web servers, unexpected
//     egress connections, setuid binaries invoked by non-root, etc.
//
// Why deferred:
//   - Needs CO-RE BPF objects compiled with the right kernel headers, OR
//     a portable libbpf load path. Both add build-time toolchain
//     requirements that contradict Lync's "single static binary" promise.
//   - Worth doing once the static phases (1-4) have field validation; a
//     flaky behavioral signal layered on top of trustworthy static scanning
//     is worse than no behavioral signal at all.
//
// Prerequisites a future implementer will need:
//   - Kernel >= 5.5 with BTF (CONFIG_DEBUG_INFO_BTF=y) on target hosts
//   - github.com/cilium/ebpf or github.com/aquasecurity/libbpfgo
//   - bpftool for CO-RE skeleton generation
//   - Compile-time check + graceful disable when host kernel lacks BTF

package monitor
