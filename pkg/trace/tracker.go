package trace

import (
	"bytes"
	"context"
	"os"

	"tulkun"
	"tulkun/pkg/trace/event"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

type ProbeCollection struct {
	Programs       map[string]ProgInterface
	Maps           map[string]MapInterface
	CollectionSpec *ebpf.CollectionSpec
	Collection     *ebpf.Collection
}

func (pc *ProbeCollection) register(p []ProgInterface, m []MapInterface) {
	for _, v := range p {
		pc.Programs[v.Name()] = v
	}

	for _, v := range m {
		pc.Maps[v.Name()] = v
	}
}

func (pc *ProbeCollection) filter(cs *ebpf.CollectionSpec) {
	// filter ebpf programs
	for name := range pc.Programs {
		prog := pc.Programs[name]
		if spec, ok := cs.Programs[prog.FuncName()]; ok {
			pc.CollectionSpec.Programs[name] = spec
		} else {
			log.Infof("drop program `%s`", prog.Name())
			// delete(cs.Programs, name)
		}
	}
	// filter ebpf maps
	if spec, ok := cs.Maps[".bss"]; ok {
		pc.CollectionSpec.Maps[".bss"] = spec
	}

	for name := range pc.Maps {
		if spec, ok := cs.Maps[name]; ok {
			pc.CollectionSpec.Maps[name] = spec
		} else {
			log.Infof("drop maps `%s`", name)
		}
	}
}

func (pc *ProbeCollection) loadCollection() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	col, err := ebpf.NewCollectionWithOptions(pc.CollectionSpec, ebpf.CollectionOptions{})
	if err != nil {
		log.Fatalf("create ebpf object collection error %s", err)
	}
	pc.Collection = col
	for name := range pc.Programs {
		prog := pc.Programs[name]
		prog.SetProgram(pc.Collection.Programs[name], pc.CollectionSpec.Programs[name])
	}
	for name := range pc.Maps {
		pc.Maps[name].SetMap(pc.Collection.Maps[name], pc.CollectionSpec.Maps[name])
	}
}

func (pc *ProbeCollection) RunWithCancel(ctx context.Context) {
	for name := range pc.Programs {
		pc.Programs[name].Attach()
	}

	for name := range pc.Maps {
		go pc.Maps[name].Start()
	}
}

func (pc *ProbeCollection) Destroy() {
	for name := range pc.Programs {
		pc.Programs[name].Detach()
	}

	for name := range pc.Maps {
		pc.Maps[name].Destroy()
	}
}

var ProbeCollections = &ProbeCollection{
	Programs: make(map[string]ProgInterface),
	Maps:     make(map[string]MapInterface),
	CollectionSpec: &ebpf.CollectionSpec{
		Maps:     make(map[string]*ebpf.MapSpec),
		Programs: make(map[string]*ebpf.ProgramSpec),
	},
}

func init() {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tulkun.BPFObjectBuffer))
	if err != nil {
		log.Fatalf("load ebpf object error %s ", err)
	}
	ProbeCollections.register(
		[]ProgInterface{
			&Kprobe{
				ProbeName:    "kprobe/udp_sendmsg",
				EbpfFuncName: "kprobe_udp_sendmsg",
				AttachPoint:  "udp_sendmsg",
			},
			&SocketFilter{
				ProbeName:    "socket/dns_filter",
				EbpfFuncName: "dns_filter_kernel",
			}, &Tracepoint{
				ProbeName:    "tracepoint/syscalls/sys_enter_execve",
				EbpfFuncName: "tracepoint_sys_enter_execve",
				AttachGroup:  "syscalls",
				AttachPoint:  "sys_enter_execve",
			},
		},
		[]MapInterface{
			&Ringbuf{
				EbpfMapName:  "socket_events",
				EventHandler: event.DNSEvent{Output: os.Stdout}.Handle,
			},
			&HashMap{
				EbpfMapName: "ports_process",
			}, &HashMap{
				EbpfMapName: "buffer_data_maps",
			}, &Ringbuf{
				EbpfMapName:  "execve_events",
				EventHandler: event.ExecveEvent{Output: os.Stdout}.Handle,
			}, &PerfRing{
				EbpfMapName:  " execve_perf",
				EventHandler: event.ExecveEvent{Output: os.Stdout}.Handle,
			},
		},
	)
	ProbeCollections.filter(spec)
	ProbeCollections.loadCollection()
}
