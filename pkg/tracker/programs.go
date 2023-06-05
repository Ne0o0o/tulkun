package tracker

import (
	"net"
	"syscall"

	"github.com/cilium/ebpf"

	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type ProgInterface interface {
	Name() string
	EbpfName() string
	Attach()
	Detach()
	SetProgram(prog *ebpf.Program, spec *ebpf.ProgramSpec)
}

type SpecInterface interface {
	Name() string
	EbpfName() string
}

type Kprobe struct {
	EbpfFuncName   string
	AttachFuncName string
	Description    string
	program        *ebpf.Program
	programSpec    *ebpf.ProgramSpec
	Link           link.Link
}

func (kp *Kprobe) Name() string {
	return kp.AttachFuncName
}

func (kp *Kprobe) EbpfName() string {
	return kp.EbpfFuncName
}

func (kp *Kprobe) Attach() {
	probe, err := link.Kprobe(kp.AttachFuncName, kp.program, nil)
	if err != nil {
		log.Errorf("attach kprobe `%s` failed %s", kp.AttachFuncName, err)
	}
	log.Infof("attach kprobe `%s` success", kp.AttachFuncName)
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
	EbpfFuncName string
	Description  string
	program      *ebpf.Program
	programSpec  *ebpf.ProgramSpec
	// net interface name
	InterfaceName string
	// socket file descriptor
	socketFD int
}

func (sf *SocketFilter) Name() string {
	return "socket_filter"
}

func (sf *SocketFilter) EbpfName() string {
	return sf.EbpfFuncName
}

func (sf *SocketFilter) Attach() {
	// create socket file descriptor
	socketFd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(HostToNetShort(syscall.ETH_P_ALL)))
	if err != nil {
		log.Errorf("attach socket filter error `%s`", err)
		return
	}
	sf.socketFD = socketFd
	// set socket
	if err := syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, sf.program.FD()); err != nil {
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
		sll := syscall.SockaddrLinklayer{
			Ifindex:  netInterface.Index,
			Protocol: HostToNetShort(syscall.ETH_P_ALL),
		}
		if err = syscall.Bind(sf.socketFD, &sll); err != nil {
			log.Errorf("set socket filter interface error `%s`", err)
		}
	}
}

func (sf *SocketFilter) Detach() {
	_ = syscall.SetsockoptInt(sf.socketFD, syscall.SOL_SOCKET, unix.SO_DETACH_BPF, sf.program.FD())
	_ = syscall.Close(sf.socketFD)
}

func (sf *SocketFilter) SetProgram(prog *ebpf.Program, spec *ebpf.ProgramSpec) {
	sf.program = prog
	sf.programSpec = spec
}
