package trace

import (
	"net"
	"strings"

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
	SectionName  string
	EbpfFuncName string
	AttachGroup  string
	AttachPoint  string
	AttachTo     string
	Description  string
	program      *ebpf.Program
	programSpec  *ebpf.ProgramSpec
	Link         link.Link
}

func (tp *Tracepoint) FuncName() string {
	return tp.EbpfFuncName
}

func (tp *Tracepoint) Name() string {
	return tp.SectionName
}

func (tp *Tracepoint) Attach() {
	probe, err := link.Tracepoint(tp.AttachGroup, tp.AttachPoint, tp.program, nil)
	if err != nil {
		log.Errorf("attach tracepoint `%s` failed %s", tp.AttachTo, err)
		return
	}
	log.Infof("attach tracepoint `%s` success", tp.AttachTo)
	tp.Link = probe
}

func (tp *Tracepoint) Detach() {
	_ = tp.Link.Close()
}

func (tp *Tracepoint) SetProgram(prog *ebpf.Program, spec *ebpf.ProgramSpec) {
	tp.SectionName = spec.SectionName
	tp.AttachTo = spec.AttachTo
	attach := strings.Split(tp.AttachTo, "/")
	if len(attach) != 2 {
		log.Errorf("invailed tracepoint `%s`", tp.AttachTo)
		return
	}
	tp.AttachGroup = attach[0]
	tp.AttachPoint = attach[1]
	tp.program = prog
	tp.programSpec = spec
}

type RawTracepoint struct {
	SectionName  string
	EbpfFuncName string
	AttachTo     string
	Description  string
	program      *ebpf.Program
	programSpec  *ebpf.ProgramSpec
	Link         link.Link
}

func (rt *RawTracepoint) FuncName() string {
	return rt.EbpfFuncName
}

func (rt *RawTracepoint) Name() string {
	return rt.SectionName
}

func (rt *RawTracepoint) Attach() {
	probe, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    rt.AttachTo,
		Program: rt.program,
	})
	if err != nil {
		log.Errorf("attach raw tracepoint `%s` failed %s", rt.AttachTo, err)
		return
	}
	log.Infof("attach raw tracepoint `%s` success", rt.AttachTo)
	rt.Link = probe
}

func (rt *RawTracepoint) Detach() {
	_ = rt.Link.Close()
}

func (rt *RawTracepoint) SetProgram(prog *ebpf.Program, spec *ebpf.ProgramSpec) {
	rt.SectionName = spec.SectionName
	rt.program = prog
	rt.programSpec = spec
}

type Kprobe struct {
	SectionName  string
	EbpfFuncName string
	AttachTo     string
	Description  string
	program      *ebpf.Program
	programSpec  *ebpf.ProgramSpec
	Link         link.Link
}

func (kp *Kprobe) FuncName() string {
	return kp.EbpfFuncName
}

func (kp *Kprobe) Name() string {
	return kp.SectionName
}

func (kp *Kprobe) Attach() {
	probe, err := link.Kprobe(kp.AttachTo, kp.program, nil)
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
	kp.SectionName = spec.SectionName
	kp.AttachTo = spec.AttachTo
	kp.program = prog
	kp.programSpec = spec
}

type Kretprobe struct {
	SectionName  string
	EbpfFuncName string
	AttachTo     string
	Description  string
	program      *ebpf.Program
	programSpec  *ebpf.ProgramSpec
	Link         link.Link
}

func (kp *Kretprobe) FuncName() string {
	return kp.EbpfFuncName
}

func (kp *Kretprobe) Name() string {
	return kp.SectionName
}

func (kp *Kretprobe) Attach() {
	probe, err := link.Kretprobe(kp.AttachTo, kp.program, nil)
	if err != nil {
		log.Errorf("attach kretprobe `%s` failed %s", kp.EbpfFuncName, err)
		return
	}
	log.Infof("attach kretprobe `%s` success", kp.EbpfFuncName)
	kp.Link = probe
}

func (kp *Kretprobe) Detach() {
	_ = kp.Link.Close()
}

func (kp *Kretprobe) SetProgram(prog *ebpf.Program, spec *ebpf.ProgramSpec) {
	kp.SectionName = spec.SectionName
	kp.AttachTo = spec.AttachTo
	kp.program = prog
	kp.programSpec = spec
}

type SocketFilter struct {
	SectionName  string
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
	return sf.SectionName
}

func (sf *SocketFilter) Attach() {
	// create socket file descriptor
	socketFd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(HostToNetShort(unix.ETH_P_ALL)))
	if err != nil {
		log.Errorf("attach socket Filter error `%s`", err)
		return
	}
	sf.socketFD = socketFd
	// set socket
	if err := unix.SetsockoptInt(socketFd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, sf.program.FD()); err != nil {
		log.Errorf("attach socket Filter error `%s`", err)
	}
	log.Infof("attach socket filter `%s` success", sf.EbpfFuncName)
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
			log.Errorf("set socket Filter interface error `%s`", err)
		}
	}
}

func (sf *SocketFilter) Detach() {
	_ = unix.SetsockoptInt(sf.socketFD, unix.SOL_SOCKET, unix.SO_DETACH_BPF, sf.program.FD())
	_ = unix.Close(sf.socketFD)
}

func (sf *SocketFilter) SetProgram(prog *ebpf.Program, spec *ebpf.ProgramSpec) {
	sf.SectionName = spec.SectionName
	sf.program = prog
	sf.programSpec = spec
}
