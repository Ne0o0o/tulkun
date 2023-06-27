package tracker

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"

	"tulkun/pkg/proc"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// basic data types define

type (
	// Domain DNS search domain
	Domain [128]byte
	IP     uint32
	Port   uint16
	// Command process commandline
	Command [64]byte
)

// Domain to string
func (d *Domain) string() string {
	//dns := bytes.TrimRight(d[:], "\x00")
	dns := bytes.Split(d[:], []byte("\x00"))[0]
	if len(dns) <= 0 {
		return ""
	}
	var pos []int
	for i := 0; i < len(dns)-1; {
		pos = append(pos, i)
		i = i + int(dns[i : i+1][0]) + 1
	}
	for _, i := range pos {
		dns[i] = []byte(".")[0]
	}
	return string(dns[1:])
}

// IP to string
func (p *IP) string() string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, *(*uint32)(p))
	return ip.String()
}

// Command to string
func (c *Command) string() string {
	return unix.ByteSliceToString(c[:])
}

/*
func (d *portVal) fileName() string {
	return string(bytes.Split(d.Comm[:], []byte("\x00"))[0])
}*/

type EventDNSMsgRaw struct {
	IFIndex uint32
	Proto   uint32
	SAddr   IP
	DAddr   IP
	SPort   uint16
	DPort   uint16
	DNS     Domain
	Pid     uint32
	Uid     uint32
	Gid     uint32
	Tgid    uint32
	Comm    Command
}

type EventDNS struct {
	MsgRaw    EventDNSMsgRaw
	Msg       map[string]interface{}
	Formatter func([]byte)
	Output    io.Writer
}

func (e EventDNS) Handle(b []byte) {
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &e.MsgRaw); err != nil {
		log.Errorf("decode data failed `%s`", err)
		return
	}
	e.Msg = make(map[string]interface{})
	e.Msg["ifindex"] = e.MsgRaw.IFIndex
	e.Msg["proto"] = e.MsgRaw.Proto
	e.Msg["saddr"] = e.MsgRaw.SAddr.string()
	e.Msg["daddr"] = e.MsgRaw.DAddr.string()
	e.Msg["sport"] = e.MsgRaw.SPort
	e.Msg["dport"] = e.MsgRaw.DPort
	e.Msg["DNS"] = e.MsgRaw.DNS.string()
	e.Msg["PID"] = e.MsgRaw.Pid
	e.Msg["uid"] = e.MsgRaw.Uid
	e.Msg["gid"] = e.MsgRaw.Gid
	e.Msg["comm"] = e.MsgRaw.Comm.string()
	ifindex, err := net.InterfaceByIndex(int(e.MsgRaw.IFIndex))
	if err == nil {
		e.Msg["ifindexName"] = ifindex.Name
	}
	// enrich process relation fields
	e.enrichProcess()

	// output msg
	msgByte, _ := json.Marshal(e.Msg)
	msgByte = append(msgByte, []byte("\n")...)
	_, _ = e.Output.Write(msgByte)
}

func (e EventDNS) enrichProcess() {
	if e.MsgRaw.Pid == 0 {
		return
	}

	p := proc.NewProcess(int32(e.MsgRaw.Pid))
	e.Msg["PPID"] = p.PPID
	e.Msg["cmdline"] = p.Cmdline
	e.Msg["cgroup"] = p.CgroupPath
	if p.Runtime != nil {
		if meta := p.InspectContainer(); meta != nil {
			e.Msg["containerId"] = meta.ContainerId
			e.Msg["containerName"] = meta.Name
			e.Msg["imageID"] = meta.ImageID
			e.Msg["imageName"] = meta.ImageName
		}
	}
}
