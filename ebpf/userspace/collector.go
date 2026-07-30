// AIVA-KS userspace collector.
// Loads the compiled eBPF objects (process_sensor.bpf.o, network_sensor.bpf.o),
// attaches them, drains the ring buffers, enriches with host metadata,
// and publishes structured JSON events to Kafka topic "raw.events".
//
// Build: requires cilium/ebpf, segmentio/kafka-go
//   go build -o bin/aiva-collector ./ebpf/userspace

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/segmentio/kafka-go"
)

// mirrors ebpf/include/events.h — field order and sizes must match exactly.
type rawEvent struct {
	TimestampNs   uint64
	Pid           uint32
	Tid           uint32
	Ppid          uint32
	Uid           uint32
	Gid           uint32
	Type          uint8
	_             [3]byte // struct padding to match C alignment
	Comm          [16]byte
	Filename      [256]byte
	Saddr         uint32
	Daddr         uint32
	Sport         uint16
	Dport         uint16
	Protocol      uint8
	_             [3]byte
	Addr          uint64
	Length        uint64
	ProtFlags     uint32
	PtraceRequest uint32
	TargetPid     uint32
	Ret           int32
}

var eventTypeNames = map[uint8]string{
	1: "execve", 2: "fork", 3: "clone", 4: "open", 5: "unlink",
	6: "connect", 7: "accept", 8: "ptrace", 9: "mprotect",
	10: "mmap", 11: "socket", 12: "bind", 13: "listen",
}

// OutEvent is what actually gets published — schema shared with
// streaming/schemas/event.schema.json
type OutEvent struct {
	Time      string `json:"time"`
	HostID    string `json:"host_id"`
	PID       uint32 `json:"pid"`
	TID       uint32 `json:"tid"`
	PPID      uint32 `json:"ppid"`
	UID       uint32 `json:"uid"`
	Comm      string `json:"comm"`
	Syscall   string `json:"syscall"`
	Category  string `json:"category"`
	Args      map[string]interface{} `json:"args"`
	ReturnCode int32  `json:"return_code"`
}

func category(t uint8) string {
	switch t {
	case 1, 2, 3:
		return "process"
	case 4, 5:
		return "file"
	case 6, 7, 11, 12, 13:
		return "network"
	case 8, 9, 10:
		return "memory"
	default:
		return "unknown"
	}
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func ipToStr(be uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, be)
	return ip.String()
}

func main() {
	hostID := os.Getenv("AIVA_HOST_ID")
	if hostID == "" {
		hostID = "unregistered-host"
	}
	kafkaBrokers := os.Getenv("AIVA_KAFKA_BROKERS")
	if kafkaBrokers == "" {
		kafkaBrokers = "localhost:9092"
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock rlimit: %v", err)
	}

	// NOTE: in production, objects are loaded via bpf2go-generated Go
	// bindings (aiva_process_sensor.go / aiva_network_sensor.go). Shown
	// here at the conceptual level — see README for the codegen step:
	//   go run github.com/cilium/ebpf/cmd/bpf2go ...
	procObjs, err := loadProcessSensorObjects()
	if err != nil {
		log.Fatalf("loading process sensor objects: %v", err)
	}
	defer procObjs.Close()

	execLink, err := link.Tracepoint("syscalls", "sys_enter_execve", procObjs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("attaching execve tracepoint: %v", err)
	}
	defer execLink.Close()

	forkLink, err := link.Tracepoint("sched", "sched_process_fork", procObjs.TraceFork, nil)
	if err != nil {
		log.Fatalf("attaching fork tracepoint: %v", err)
	}
	defer forkLink.Close()

	rd, err := ringbuf.NewReader(procObjs.Events)
	if err != nil {
		log.Fatalf("opening ring buffer reader: %v", err)
	}
	defer rd.Close()

	writer := &kafka.Writer{
		Addr:     kafka.TCP(kafkaBrokers),
		Topic:    "raw.events",
		Balancer: &kafka.Hash{}, // partition by key = host_id (ordering per host)
	}
	defer writer.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	log.Printf("aiva-collector started host_id=%s kafka=%s", hostID, kafkaBrokers)

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("ring buffer read error: %v", err)
			continue
		}

		var re rawEvent
		if err := binaryUnmarshal(record.RawSample, &re); err != nil {
			log.Printf("decode error: %v", err)
			continue
		}

		out := OutEvent{
			Time:     time.Unix(0, int64(re.TimestampNs)).UTC().Format(time.RFC3339Nano),
			HostID:   hostID,
			PID:      re.Pid,
			TID:      re.Tid,
			PPID:     re.Ppid,
			UID:      re.Uid,
			Comm:     cstr(re.Comm[:]),
			Syscall:  eventTypeNames[re.Type],
			Category: category(re.Type),
			Args:     map[string]interface{}{},
			ReturnCode: re.Ret,
		}

		switch re.Type {
		case 1: // execve
			out.Args["filename"] = cstr(re.Filename[:])
		case 6: // connect
			out.Args["saddr"] = ipToStr(re.Saddr)
			out.Args["daddr"] = ipToStr(re.Daddr)
			out.Args["sport"] = re.Sport
			out.Args["dport"] = re.Dport
		case 8: // ptrace
			out.Args["ptrace_request"] = re.PtraceRequest
			out.Args["target_pid"] = re.TargetPid
		case 9: // mprotect
			out.Args["addr"] = re.Addr
			out.Args["length"] = re.Length
			out.Args["prot_flags"] = re.ProtFlags
		}

		payload, err := json.Marshal(out)
		if err != nil {
			log.Printf("marshal error: %v", err)
			continue
		}

		err = writer.WriteMessages(ctx, kafka.Message{
			Key:   []byte(hostID),
			Value: payload,
		})
		if err != nil && ctx.Err() == nil {
			log.Printf("kafka write error: %v", err)
		}
	}
}
