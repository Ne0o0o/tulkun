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
	// return string(bytes.TrimRight(c[:], "\x00"))
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

type EventDNSMsg struct {
	IFIndex uint32
	Proto   uint32
	SAddr   string
	DAddr   string
	SPort   uint16
	DPort   uint16
	DNS     string
	Pid     uint32
	Uid     uint32
	Gid     uint32
	Tgid    uint32
	Comm    string
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
	/*
		e.Msg = EventDNSMsg{
			IFIndex: e.MsgRaw.IFIndex,
			Proto:   e.MsgRaw.Proto,
			SAddr:   e.MsgRaw.SAddr.string(),
			DAddr:   e.MsgRaw.DAddr.string(),
			SPort:   e.MsgRaw.SPort,
			DPort:   e.MsgRaw.DPort,
			DNS:     e.MsgRaw.DNS.string(),
			Pid:     e.MsgRaw.Pid,
			Uid:     e.MsgRaw.Uid,
			Gid:     e.MsgRaw.Gid,
			Tgid:    e.MsgRaw.Tgid,
			Comm:    e.MsgRaw.Comm.string(),
		}*/

	e.Msg["IFIndex"] = e.MsgRaw.IFIndex
	e.Msg["Proto"] = e.MsgRaw.Proto
	e.Msg["SAddr"] = e.MsgRaw.SAddr.string()
	e.Msg["DAddr"] = e.MsgRaw.DAddr.string()
	e.Msg["SPort"] = e.MsgRaw.SPort
	e.Msg["DPort"] = e.MsgRaw.DPort
	e.Msg["DNS"] = e.MsgRaw.DNS.string()
	e.Msg["PID"] = e.MsgRaw.Pid
	e.Msg["UID"] = e.MsgRaw.Uid
	e.Msg["GID"] = e.MsgRaw.Gid
	e.Msg["Comm"] = e.MsgRaw.Comm.string()

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
	if p.Runtime != nil {
		if meta := p.InspectContainer(); meta != nil {
			e.Msg["ContainerId"] = meta.ContainerId
			e.Msg["ContainerName"] = meta.Name
			e.Msg["ImageName"] = meta.Image
		}
	}
}
