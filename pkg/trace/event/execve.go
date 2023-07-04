package event

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type (
	Filename [128]byte
	Argv     [128]byte
	Envp     [128]byte
)

type ExecveMsgRaw struct {
	Pid      uint32
	Uid      uint32
	Gid      uint32
	Tgid     uint32
	Filename Filename
	Argv     Argv
	Envp     Envp
}

func (fn *Filename) string() string {
	//return string(bytes.Split(fn[:], []byte("\x00"))[0])
	return unix.ByteSliceToString(fn[:])
}

func (argv *Argv) string() string {
	return unix.ByteSliceToString(argv[:])
}

func (envp *Envp) string() string {
	return unix.ByteSliceToString(envp[:])
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
	e.Msg["filename"] = e.MsgRaw.Filename.string()
	// enrich process relation fields
	// enrichProcess(int32(e.MsgRaw.Pid), e.Msg)

	// output msg
	msgByte, _ := json.Marshal(e.Msg)
	msgByte = append(msgByte, []byte("\n")...)
	_, _ = e.Output.Write(msgByte)
}
