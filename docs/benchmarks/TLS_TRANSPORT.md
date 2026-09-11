# TLS transport benchmark

This benchmark compares two local, in-process paths with the same bidirectional payload:

- a raw pass-through bridge;
- the verified TLS bridge, including downstream and upstream handshakes.

It uses only ephemeral loopback listeners and test certificates. It never contacts an external service or changes a trust store. Certificate generation and connection teardown are outside the timed region; transfer includes one payload in each direction. Two warm-up samples per mode are not reported. Peak process memory is sampled every 5 ms and includes the Rust test harness.

Run the release benchmark with:

```sh
npm run benchmark:tls
```

The defaults are 20 samples, four concurrent connections and a 1 MiB payload in each direction. Override them with `SIPPIN_BENCH_SAMPLES` (3-500), `SIPPIN_BENCH_CONCURRENCY` (1-64) and `SIPPIN_BENCH_PAYLOAD_MIB` (1-64). The command emits one `SIPPIN_TLS_BENCHMARK=` JSON record suitable for archival or comparison.

## Initial Windows baseline

Recorded on 2026-09-11 with an optimized build and Cargo 1.98.1.

| Item | Value |
| --- | ---: |
| OS / architecture | Windows / x86_64 |
| CPU | AMD Ryzen 7 7800X3D, 16 logical CPUs |
| Physical memory | 31,895 MiB |
| Payload | 1,048,576 bytes each direction |
| Samples / concurrency | 20 / 4 |
| Pass-through p50 / p95 | 2.486 ms / 2.732 ms |
| Verified TLS p50 / p95 | 4.733 ms / 30.722 ms |
| Pass-through throughput | 2,533 MiB/s |
| Verified TLS throughput | 413 MiB/s |
| Pass-through / TLS peak process memory | 12.55 MiB / 18.41 MiB |
| TLS p50 overhead | 90.34% |

This is a development baseline, not an acceptance threshold. Loopback results are sensitive to scheduler activity, antivirus and power state; the TLS p95 in particular needs repeated runs. TLS runs after pass-through in the same process, so its peak-memory value may include allocations retained by the first mode. Before accepting the network-core decision, collect repeated Windows/macOS/Linux results, add sustained and larger-payload workloads, and compare the same workload with the scoped C++ candidate described in ADR 0001.
