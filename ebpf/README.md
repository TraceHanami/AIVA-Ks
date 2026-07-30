# eBPF Sensor Layer

## Toolchain
- clang/LLVM >= 15, libbpf >= 1.3, `bpftool` for `vmlinux.h` generation
- Go 1.22+ with `github.com/cilium/ebpf` for userspace loading (bpf2go codegen)

## Build steps

```bash
# 1. Generate vmlinux.h for CO-RE (once per target kernel)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/include/vmlinux.h

# 2. Generate Go bindings + compile BPF objects via bpf2go
cd ebpf/userspace
go run github.com/cilium/ebpf/cmd/bpf2go \
    -cc clang -cflags "-O2 -g -Wall -target bpf" \
    ProcessSensor ../src/process_sensor.bpf.c -- -I../include
go run github.com/cilium/ebpf/cmd/bpf2go \
    -cc clang -cflags "-O2 -g -Wall -target bpf" \
    NetworkSensor ../src/network_sensor.bpf.c -- -I../include

# This produces processsensor_bpfel.go / networksensor_bpfel.go with
# generated *Objects structs (procObjs.TraceExecve etc. in collector.go).

# 3. Build the collector binary
go build -o ../../bin/aiva-collector .
```

## Running

Requires `CAP_BPF` + `CAP_PERFMON` (kernel >= 5.8) or root.

```bash
sudo AIVA_HOST_ID=$(hostname) AIVA_KAFKA_BROKERS=localhost:9092 ./bin/aiva-collector
```

## Notes on collector.go

`collector.go` shows the intended structure and event decoding logic.
`loadProcessSensorObjects()` and the `binaryUnmarshal` ring-buffer decode
helper are produced/used per the bpf2go workflow above — bpf2go generates
the `loadProcessSensorObjects` function and typed `*Objects` struct for you;
`binaryUnmarshal` is a thin wrapper around `encoding/binary.Read` with a
`binary.LittleEndian` reader over `bytes.NewReader(raw)`, matching the
`struct aiva_event` layout in `include/events.h` field-for-field. Struct
padding (the `_ [3]byte` fields) exists because cgo/C struct alignment
differs from Go's default packing — verify with `pahole` on the compiled
BPF object if you change the struct.
