package tracker

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	log "github.com/sirupsen/logrus"
)

type MetaKey struct {
	Proto uint32
	SAddr uint32
	DAddr uint32
	SPort uint16
	DPort uint16
}

type ProcessVal struct {
	Pid  uint32
	Uid  uint32
	Gid  uint32
	Tgid uint32
	Comm [64]byte
}

type MapInterface interface {
	Name() string
	SetMap(m *ebpf.Map, spec *ebpf.MapSpec)
	Start()
	Destroy()
}

type Ringbuf struct {
	EbpfMapName  string
	MapSpec      *ebpf.MapSpec
	Map          *ebpf.Map
	Reader       *ringbuf.Reader
	EventHandler func([]byte)
}

func (rb *Ringbuf) Name() string {
	return rb.EbpfMapName
}

func (rb *Ringbuf) Start() {
	rb.Reader, _ = ringbuf.NewReader(rb.Map)
	for {
		record, err := rb.Reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Errorf("received signal, exiting ringbuf `%s`", rb.Name())
				return
			}
			log.Errorf("ringbuf `%s` error %s", rb.Name(), err)
			continue
		}
		rb.EventHandler(record.RawSample)
	}
}

func (rb *Ringbuf) Destroy() {
	_ = rb.Reader.Close()
}

func (rb *Ringbuf) SetMap(m *ebpf.Map, spec *ebpf.MapSpec) {
	rb.Map = m
	rb.MapSpec = spec
}

type HashMap struct {
	EbpfMapName  string
	MapSpec      *ebpf.MapSpec
	Map          *ebpf.Map
	Reader       *ringbuf.Reader
	EventHandler func([]byte)
}

func (h *HashMap) Name() string {
	return h.EbpfMapName
}

func (h *HashMap) Start() {
}

func (h *HashMap) Destroy() {
	_ = h.Map.Close()
}

func (h *HashMap) SetMap(m *ebpf.Map, spec *ebpf.MapSpec) {
	h.Map = m
	h.MapSpec = spec
}
