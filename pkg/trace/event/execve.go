package event

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

type ExecveMsgRaw struct {
	Process  Process
	Filename Filename
	Argv     BufArrayStr
	// Envp     Envp
}

type ExecveEvent struct {
	MsgRaw    ExecveMsgRaw
	Msg       map[string]interface{}
	Formatter func([]byte)
	Output    io.Writer
}

func (e ExecveEvent) Handle(b []byte) {
	fmt.Println(len(b), b)
	return
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &e.MsgRaw); err != nil {
		// log.Errorf("decode data failed `%s`", err)
		return
	}
	e.Msg = make(map[string]interface{})
	e.Msg["PID"] = e.MsgRaw.Process.PID
	e.Msg["uid"] = e.MsgRaw.Process.UID
	e.Msg["gid"] = e.MsgRaw.Process.GID
	e.Msg["filename"] = e.MsgRaw.Filename.string()
	e.Msg["argv"] = e.MsgRaw.Argv.stringArray()
	// e.Msg["envp"] = e.MsgRaw.Envp.string()
	// enrich process relation fields
	// enrichProcess(int32(e.MsgRaw.Pid), e.Msg)

	// output msg
	msgByte, _ := json.Marshal(e.Msg)
	msgByte = append(msgByte, []byte("\n")...)
	_, _ = e.Output.Write(msgByte)
}
