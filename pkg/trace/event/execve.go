package event

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"

	log "github.com/sirupsen/logrus"
)

type Filename [128]byte

type ExecveMsgRaw struct {
	Pid      uint32
	Filename Filename
}

func (fn *Filename) string() string {
	return string(bytes.Split(fn[:], []byte("\x00"))[0])
}

type ExecveEvent struct {
	MsgRaw    ExecveMsgRaw
	Msg       map[string]interface{}
	Formatter func([]byte)
	Output    io.Writer
}

func (e ExecveEvent) Handle(b []byte) {
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &e.MsgRaw); err != nil {
		log.Errorf("decode data failed `%s`", err)
		return
	}
	e.Msg = make(map[string]interface{})
	e.Msg["PID"] = e.MsgRaw.Pid
	e.Msg["filename"] = e.MsgRaw.Filename
	// enrich process relation fields
	// enrichProcess(int32(e.MsgRaw.Pid), e.Msg)

	// output msg
	msgByte, _ := json.Marshal(e.Msg)
	msgByte = append(msgByte, []byte("\n")...)
	_, _ = e.Output.Write(msgByte)
}
