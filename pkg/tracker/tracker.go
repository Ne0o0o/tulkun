package tracker

import (
	"bytes"
	"context"
	"os"

	"tulkun"

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
		pc.Programs[v.EbpfName()] = v
	}

	for _, v := range m {
		pc.Maps[v.Name()] = v
	}
}

func (pc *ProbeCollection) filter(cs *ebpf.CollectionSpec) {
	// filter ebpf programs
	for name := range pc.Programs {
		if spec, ok := cs.Programs[name]; ok {
			pc.CollectionSpec.Programs[name] = spec
		} else {
			delete(cs.Programs, name)
		}
	}
	// filter ebpf maps
	for name := range pc.Maps {
		if spec, ok := cs.Maps[name]; ok {
			pc.CollectionSpec.Maps[name] = spec
		} else {
			delete(cs.Maps, name)
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
		a := pc.Programs[name]
		a.SetProgram(pc.Collection.Programs[name], pc.CollectionSpec.Programs[name])
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
				EbpfFuncName:   "kprobe_udp_sendmsg",
				AttachFuncName: "udp_sendmsg",
			},
			&SocketFilter{
				EbpfFuncName: "dns_filter_kernel",
			},
		},
		[]MapInterface{
			&Ringbuf{
				EbpfMapName:  "socket_events",
				EventHandler: EventDNS{Output: os.Stdout}.Handle,
			},
			&HashMap{
				EbpfMapName: "ports_process",
			},
		},
	)
	ProbeCollections.filter(spec)
	ProbeCollections.loadCollection()
}
