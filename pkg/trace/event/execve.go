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
	Buffer  Buffer
}

const (
	argv = iota
	envp
)

var syscallArgs = map[int]string{
	argv: "argv",
	envp: "envp",
}

type ExecveEvent struct {
	MsgRaw    ExecveMsgRaw
	Msg       map[string]interface{}
	Formatter func([]byte)
	Output    io.Writer
}

func (e ExecveEvent) Handle(b []byte) {
	var offset = 0

	offset = int(unsafe.Sizeof(e.MsgRaw.Context))
	if err := binary.Read(bytes.NewBuffer(b[:offset]), binary.LittleEndian, &e.MsgRaw.Context); err != nil {
		log.Errorf("handler decode event context failed `%s`", err)
		return
	}
	e.MsgRaw.Buffer.argNum = binary.LittleEndian.Uint32(b[offset : offset+4])
	e.MsgRaw.Buffer.bufferSize = binary.LittleEndian.Uint32(b[offset+4 : offset+8])
	offset += 8
	e.MsgRaw.Buffer.buffer = b[offset : offset+int(e.MsgRaw.Buffer.bufferSize)]

	// fill message
	e.Msg = *e.MsgRaw.Context.fill()

	buffer := e.MsgRaw.Buffer.string()
	e.Msg[syscallArgs[argv]] = buffer[argv]
	e.Msg[syscallArgs[envp]] = buffer[envp]

	// enrich runtime relation fields
	enrichRuntime(e.MsgRaw.Context.Task.CgroupID, e.Msg)
	// output msg
	msgByte, _ := json.Marshal(e.Msg)
	msgByte = append(msgByte, []byte("\n")...)
	_, _ = e.Output.Write(msgByte)
}
