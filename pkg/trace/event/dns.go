package event

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"

	log "github.com/sirupsen/logrus"
)

type DNSMsgRaw struct {
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

type DNSEvent struct {
	MsgRaw    DNSMsgRaw
	Msg       map[string]interface{}
	Formatter func([]byte)
	Output    io.Writer
}

func (e DNSEvent) Handle(b []byte) {
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
	iface, err := net.InterfaceByIndex(int(e.MsgRaw.IFIndex))
	if err == nil {
		e.Msg["ifname"] = iface.Name
	}
	// enrich process relation fields
	enrichProcess(int32(e.MsgRaw.Pid), e.Msg)

	// output msg
	msgByte, _ := json.Marshal(e.Msg)
	msgByte = append(msgByte, []byte("\n")...)
	_, _ = e.Output.Write(msgByte)
}
