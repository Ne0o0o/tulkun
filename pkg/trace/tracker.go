package trace

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"

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

func (pc *ProbeCollection) registerBatch(p []ProgInterface, m []MapInterface) {
	for _, v := range p {
		pc.Programs[v.FuncName()] = v
	}

	for _, v := range m {
		pc.Maps[v.Name()] = v
	}
}

func (pc *ProbeCollection) registerProgram(p ProgInterface) {
	if _, ok := pc.Programs[p.FuncName()]; !ok {
		pc.Programs[p.FuncName()] = p
	} else {
		log.Info("program `%s` is already exist", p.FuncName())
	}
}

func (pc *ProbeCollection) registerMap(m MapInterface) {
	if _, ok := pc.Maps[m.Name()]; !ok {
		pc.Maps[m.Name()] = m
	} else {
		log.Info("map `%s` is already exist", m.Name())
	}
}

func (pc *ProbeCollection) loadCollections() {
	// set programs
	for name := range pc.Programs {
		pc.Programs[name].SetProgram(pc.Collection.Programs[name], pc.CollectionSpec.Programs[name])
	}
	// set maps
	for name := range pc.Maps {
		pc.Maps[name].SetMap(pc.Collection.Maps[name], pc.CollectionSpec.Maps[name])
	}
}

func (pc *ProbeCollection) LoadCollectionFromFilter(spec *ebpf.CollectionSpec) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	// set runtime spec
	pc.CollectionSpec = spec
	// load runtime collections
	col, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		log.Fatalf("create ebpf object collection error %s", err)
	}
	pc.Collection = col
	// set ebpf programs
	for name := range pc.Programs {
		prog := pc.Programs[name]
		if ps, ok := spec.Programs[prog.FuncName()]; ok {
			pc.CollectionSpec.Programs[name] = ps
		} else {
			log.Infof("drop program `%s`", prog.Name())
		}
	}
	// set maps for static
	if ps, ok := spec.Maps[".bss"]; ok {
		pc.CollectionSpec.Maps[".bss"] = ps
	}

	// set ebpf maps
	for name := range pc.Maps {
		if ps, ok := spec.Maps[name]; ok {
			pc.CollectionSpec.Maps[name] = ps
		} else {
			log.Infof("drop maps `%s`", name)
		}
	}
	pc.loadCollections()
}

func (pc *ProbeCollection) LoadCollectionFromSpec(spec *ebpf.CollectionSpec) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	// set runtime spec
	pc.CollectionSpec = spec
	// load runtime collections
	col, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		log.Fatalf("create ebpf object collection error %s", err)
	}
	pc.Collection = col
	// set ebpf programs
	for name := range spec.Programs {
		switch spec.Programs[name].Type {
		case ebpf.Kprobe:
			if strings.HasPrefix(spec.Programs[name].SectionName, "kretprobe/") {
				pc.registerProgram(&Kretprobe{
					EbpfFuncName: spec.Programs[name].Name,
				})
			} else if strings.HasPrefix(spec.Programs[name].SectionName, "kprobe/") {
				pc.registerProgram(&Kprobe{
					EbpfFuncName: spec.Programs[name].Name,
				})
			} else {
				// TODO: uprobe

			}
		case ebpf.TracePoint:
			pc.registerProgram(&Tracepoint{
				EbpfFuncName: spec.Programs[name].Name,
			})
		case ebpf.RawTracepoint:
			pc.registerProgram(&RawTracepoint{
				EbpfFuncName: spec.Programs[name].Name,
			})
		case ebpf.SocketFilter:
			pc.registerProgram(&SocketFilter{
				EbpfFuncName: spec.Programs[name].Name,
			})
		}
	}
	// set ebpf maps
	for name := range spec.Maps {
		switch spec.Maps[name].Type {
		case ebpf.Hash, ebpf.LRUHash, ebpf.Array, ebpf.PerCPUArray:
			pc.registerMap(&HashMap{
				EbpfMapName: spec.Maps[name].Name,
			})
		case ebpf.PerfEventArray:
			var handler func(b []byte)
			if _, ok := DefaultMapHandler[name]; ok {
				handler = DefaultMapHandler[name]
			}
			pc.registerMap(&PerfRing{
				EbpfMapName:  spec.Maps[name].Name,
				EventHandler: handler,
			})
		case ebpf.RingBuf:
			var handler func(b []byte)
			if _, ok := DefaultMapHandler[name]; ok {
				handler = DefaultMapHandler[name]
			}
			pc.registerMap(&Ringbuf{
				EbpfMapName:  spec.Maps[name].Name,
				EventHandler: handler,
			})
		}
	}
	pc.loadCollections()
}

func (pc *ProbeCollection) ResetMaps(mapList []MapInterface) {
	for _, m := range mapList {
		if _, ok := pc.Maps[m.Name()]; ok {
			pc.Maps[m.Name()] = m
			pc.Maps[m.Name()].SetMap(pc.Collection.Maps[m.Name()], pc.CollectionSpec.Maps[m.Name()])
		} else {
			log.Errorf("reset map error `%s` not exist", m.Name())
		}
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

var DefaultMapHandler = map[string]func([]byte){
	"dns_event":     event.PrintStringHandler,
	"socket_events": event.DNSEvent{Output: os.Stdout}.Handle,
	"syscall_event": event.SyscallEvent{Output: os.Stdout}.Handle,
}

func NewTracker(bpfObjectBuffer []byte) (*ProbeCollection, error) {
	if bpfObjectBuffer == nil {
		return nil, errors.New("empty bpf object")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObjectBuffer))
	if err != nil {
		return nil, err
	}
	collections := &ProbeCollection{
		Programs: make(map[string]ProgInterface),
		Maps:     make(map[string]MapInterface),
		CollectionSpec: &ebpf.CollectionSpec{
			Maps:     make(map[string]*ebpf.MapSpec),
			Programs: make(map[string]*ebpf.ProgramSpec),
		},
	}
	collections.LoadCollectionFromSpec(spec)
	return collections, nil
}
