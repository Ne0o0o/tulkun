package event

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"unsafe"

	log "github.com/sirupsen/logrus"
)

type ExecveMsgRaw struct {
	Context SyscallContext
	Buffer  StrArrayBuffer
}

type ExecveEvent struct {
	MsgRaw    ExecveMsgRaw
	Msg       map[string]interface{}
	Formatter func([]byte)
	Output    io.Writer
}

func (e ExecveEvent) Handle(b []byte) {
	if err := binary.Read(bytes.NewBuffer(b[:unsafe.Sizeof(e.MsgRaw.Context)]), binary.LittleEndian, &e.MsgRaw.Context); err != nil {
		log.Errorf("decode context failed `%s`", err)
		return
	}
	e.MsgRaw.Buffer.buffer = b[unsafe.Sizeof(e.MsgRaw.Context):]
	e.Msg = *e.MsgRaw.Context.fill()
	e.Msg["argv"] = e.MsgRaw.Buffer.string()
	// enrich process relation fields
	enrichProcess(int32(e.MsgRaw.Context.Task.HostPID), e.Msg)

	// output msg
	msgByte, _ := json.Marshal(e.Msg)
	msgByte = append(msgByte, []byte("\n")...)
	_, _ = e.Output.Write(msgByte)
}
