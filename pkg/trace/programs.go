package trace

import (
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type ProgInterface interface {
	Name() string
	FuncName() string
	Attach()
	Detach()
	SetProgram(prog *ebpf.Program, spec *ebpf.ProgramSpec)
}

type Tracepoint struct {
	ProbeName    string
	EbpfFuncName string
	AttachGroup  string
	AttachPoint  string
	Description  string
	program      *ebpf.Program
	programSpec  *ebpf.ProgramSpec
	Link         link.Link
}

func (tp *Tracepoint) FuncName() string {
	return tp.EbpfFuncName
}

func (tp *Tracepoint) Name() string {
	return tp.ProbeName
}

func (tp *Tracepoint) Attach() {
	probe, err := link.Tracepoint(tp.AttachGroup, tp.AttachPoint, tp.program, nil)
	if err != nil {
		log.Errorf("attach tracepoint `%s` failed %s", tp.AttachPoint, err)
		return
	}
	log.Infof("attach tracepoint `%s` success", tp.AttachPoint)
	tp.Link = probe
}

func (tp *Tracepoint) Detach() {
	_ = tp.Link.Close()
}

func (tp *Tracepoint) SetProgram(prog *ebpf.Program, spec *ebpf.ProgramSpec) {
	tp.program = prog
	tp.programSpec = spec
}

type RawTracepoint struct {
	ProbeName    string
	EbpfFuncName string
	AttachPoint  string
	Description  string
	program      *ebpf.Program
	programSpec  *ebpf.ProgramSpec
	Link         link.Link
}

func (rt *RawTracepoint) FuncName() string {
	return rt.EbpfFuncName
}

func (rt *RawTracepoint) Name() string {
	return rt.ProbeName
}

func (rt *RawTracepoint) Attach() {
	probe, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    rt.AttachPoint,
		Program: rt.program,
	})
	if err != nil {
		log.Errorf("attach raw tracepoint `%s` failed %s", rt.AttachPoint, err)
		return
	}
	log.Infof("attach raw tracepoint `%s` success", rt.AttachPoint)
	rt.Link = probe
}

func (rt *RawTracepoint) Detach() {
	_ = rt.Link.Close()
}

func (rt *RawTracepoint) SetProgram(prog *ebpf.Program, spec *ebpf.ProgramSpec) {
	rt.program = prog
	rt.programSpec = spec
}

type Kprobe struct {
	ProbeName    string
	EbpfFuncName string
	AttachPoint  string
	Description  string
	program      *ebpf.Program
	programSpec  *ebpf.ProgramSpec
	Link         link.Link
}

func (kp *Kprobe) FuncName() string {
	return kp.EbpfFuncName
}

func (kp *Kprobe) Name() string {
	return kp.ProbeName
}

func (kp *Kprobe) Attach() {
	probe, err := link.Kprobe(kp.AttachPoint, kp.program, nil)
	if err != nil {
		log.Errorf("attach kprobe `%s` failed %s", kp.EbpfFuncName, err)
		return
	}
	log.Infof("attach kprobe `%s` success", kp.EbpfFuncName)
	kp.Link = probe
}

func (kp *Kprobe) Detach() {
	_ = kp.Link.Close()
}

func (kp *Kprobe) SetProgram(prog *ebpf.Program, spec *ebpf.ProgramSpec) {
	kp.program = prog
	kp.programSpec = spec
}

type SocketFilter struct {
	ProbeName    string
	EbpfFuncName string
	Description  string
	program      *ebpf.Program
	programSpec  *ebpf.ProgramSpec
	// net interface name
	InterfaceName string
	// socket file descriptor
	socketFD int
}

func (sf *SocketFilter) FuncName() string {
	return sf.EbpfFuncName
}

func (sf *SocketFilter) Name() string {
	return sf.ProbeName
}

func (sf *SocketFilter) Attach() {
	// create socket file descriptor
	socketFd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(HostToNetShort(unix.ETH_P_ALL)))
	if err != nil {
		log.Errorf("attach socket filter error `%s`", err)
		return
	}
	sf.socketFD = socketFd
	// set socket
	if err := unix.SetsockoptInt(socketFd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, sf.program.FD()); err != nil {
		log.Errorf("attach socket filter error `%s`", err)
	}
	log.Infof("attach socket filter success")
	// set net interface
	if sf.InterfaceName != "" {
		netInterface, err := net.InterfaceByName(sf.InterfaceName)
		if err != nil {
			log.Errorf("get net interface error `%s`", err)
			return
		}
		sll := unix.SockaddrLinklayer{
			Ifindex:  netInterface.Index,
			Protocol: HostToNetShort(unix.ETH_P_ALL),
		}
		if err = unix.Bind(sf.socketFD, &sll); err != nil {
			log.Errorf("set socket filter interface error `%s`", err)
		}
	}
}

func (sf *SocketFilter) Detach() {
	_ = unix.SetsockoptInt(sf.socketFD, unix.SOL_SOCKET, unix.SO_DETACH_BPF, sf.program.FD())
	_ = unix.Close(sf.socketFD)
}

func (sf *SocketFilter) SetProgram(prog *ebpf.Program, spec *ebpf.ProgramSpec) {
	sf.program = prog
	sf.programSpec = spec
}
