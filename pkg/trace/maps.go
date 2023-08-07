package trace

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	log "github.com/sirupsen/logrus"
)

type MapInterface interface {
	Name() string
	SetMap(m *ebpf.Map, spec *ebpf.MapSpec)
	Start()
	Destroy()
}

type PerfRing struct {
	EbpfMapName  string
	MapSpec      *ebpf.MapSpec
	Map          *ebpf.Map
	Reader       *perf.Reader
	EventHandler func([]byte)
}

func (pr *PerfRing) Name() string {
	return pr.EbpfMapName
}

func (pr *PerfRing) Start() {
	pr.Reader, _ = perf.NewReader(pr.Map, 1024)
	log.Infof("attach perfring `%s` success", pr.Name())
	for {
		record, err := pr.Reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Infof("received signal, exiting perf ring `%s`", pr.Name())
				return
			}
			log.Errorf("perf event `%s` error %s", pr.Name(), err)
			continue
		}
		pr.EventHandler(record.RawSample)
	}
}

func (pr *PerfRing) Destroy() {
	_ = pr.Reader.Close()
}

func (pr *PerfRing) SetMap(m *ebpf.Map, spec *ebpf.MapSpec) {
	pr.Map = m
	pr.MapSpec = spec
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
	log.Infof("attach ringbuf `%s` success", rb.Name())
	for {
		record, err := rb.Reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Infof("received signal, exiting ringbuf `%s`", rb.Name())
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
	EbpfMapName string
	MapSpec     *ebpf.MapSpec
	Map         *ebpf.Map
	// Reader      *ringbuf.Reader
	// EventHandler func([]byte)
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
