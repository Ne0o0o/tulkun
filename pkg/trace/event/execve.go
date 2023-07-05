package event

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"

	log "github.com/sirupsen/logrus"
)

type ExecveMsgRaw struct {
	Pid      uint32
	Uid      uint32
	Gid      uint32
	Tgid     uint32
	Filename Filename
	Argv     BufArrStr
	// Envp     Envp
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
	e.Msg["uid"] = e.MsgRaw.Uid
	e.Msg["gid"] = e.MsgRaw.Gid
	e.Msg["filename"] = e.MsgRaw.Filename.string()
	//e.Msg["argv"] = e.MsgRaw.Argv.string()
	// e.Msg["envp"] = e.MsgRaw.Envp.string()
	// enrich process relation fields
	// enrichProcess(int32(e.MsgRaw.Pid), e.Msg)

	// output msg
	msgByte, _ := json.Marshal(e.Msg)
	msgByte = append(msgByte, []byte("\n")...)
	_, _ = e.Output.Write(msgByte)
}
