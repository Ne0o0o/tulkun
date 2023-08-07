package event

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

/*
	typedef struct task_context
	{
	    u64 start_time; // thread's start time
	    u64 cgroup_id;
	    u32 pid;       // PID as in the userspace term
	    u32 tid;       // TID as in the userspace term
	    u32 ppid;      // Parent PID as in the userspace term
	    u32 host_pid;  // PID in host pid namespace
	    u32 host_tid;  // TID in host pid namespace
	    u32 host_ppid; // Parent PID in host pid namespace
	    u32 uid;
	    u32 mnt_id;
	    u32 pid_id;
		char tty[TASK_COMM_LEN];
	    char comm[TASK_COMM_LEN];
	    char uts_name[TASK_COMM_LEN];
	    u32 flags;

	} task_context_t;
*/

var (
	SyscallHandlerMap = make(map[int]func(SyscallBuffer) *map[string]interface{})
	bootTime          uint64
)

type TaskContext struct {
	StartTime uint64
	CgroupID  uint64
	PID       uint32
	TID       uint32
	PPID      uint32
	HostPID   uint32
	HostTID   uint32
	HostPPID  uint32
	UID       uint32
	MntID     uint32
	PIDID     uint32
	TTY       [TaskLen16]byte
	Comm      [TaskLen16]byte
	UtsName   [TaskLen16]byte
	Stdin     [TaskLen16]byte
	Stdout    [TaskLen16]byte
	Flag      uint32
}

type SyscallContext struct {
	Timestamp   uint64
	Task        TaskContext
	SyscallID   uint32
	ProcessorID uint16
	Argnum      uint32
}

// SyscallBuffer Buffer syscall buffer
type SyscallBuffer struct {
	argNum     uint32
	bufferSize uint32
	buffer     []byte
}

type SyscallEvent struct {
	// raw data
	SyscallCtxRaw    SyscallContext
	SyscallBufferRaw SyscallBuffer
	// output
	Formatter func([]byte)
	OutputMsg map[string]interface{}
	Output    io.Writer
}

func (tc TaskContext) fill() *map[string]interface{} {
	var task = make(map[string]interface{})
	task["startTime"] = tc.StartTime/100 + bootTime
	task["cgroupId"] = tc.CgroupID
	task["pid"] = tc.PID
	task["tid"] = tc.TID
	task["ppid"] = tc.PPID
	task["hostPID"] = tc.HostPID
	task["hostTID"] = tc.HostTID
	task["hostPPID"] = tc.HostPPID
	task["uid"] = tc.UID
	task["mntId"] = tc.MntID
	task["pidId"] = tc.PIDID
	task["tty"] = unix.ByteSliceToString(tc.TTY[:])
	task["comm"] = unix.ByteSliceToString(tc.Comm[:])
	task["utsName"] = unix.ByteSliceToString(tc.UtsName[:])
	task["stdin"] = unix.ByteSliceToString(tc.Stdin[:])
	task["stdout"] = unix.ByteSliceToString(tc.Stdout[:])
	task["flag"] = tc.Flag
	return &task
}

func (sc SyscallContext) fill() *map[string]interface{} {
	var syscallCtx = make(map[string]interface{})
	syscallCtx["timestamp"] = sc.Timestamp
	syscallCtx["syscallID"] = sc.SyscallID
	syscallCtx["processorID"] = sc.ProcessorID
	syscallCtx["task"] = *sc.Task.fill()
	return &syscallCtx
}

func (se SyscallEvent) Handle(b []byte) {
	var offset = 0
	offset = int(unsafe.Sizeof(se.SyscallCtxRaw))

	// put syscall context
	if err := binary.Read(bytes.NewBuffer(b[:offset]), binary.LittleEndian, &se.SyscallCtxRaw); err != nil {
		log.Errorf("handler decode syscall context failed `%s`", err)
		return
	}
	se.OutputMsg = *se.SyscallCtxRaw.fill()

	// put syscall buffer
	se.SyscallBufferRaw.argNum = binary.LittleEndian.Uint32(b[offset : offset+4])
	se.SyscallBufferRaw.bufferSize = binary.LittleEndian.Uint32(b[offset+4 : offset+8])
	offset += 8
	se.SyscallBufferRaw.buffer = b[offset : offset+int(se.SyscallBufferRaw.bufferSize)]

	if handler, ok := SyscallHandlerMap[int(se.SyscallCtxRaw.SyscallID)]; ok {
		se.fillOutput(handler(se.SyscallBufferRaw))
	} else {
		log.Errorf("miss handler for syscall ID `%d`", se.SyscallCtxRaw.SyscallID)
	}

	// enrich runtime relation fields
	se.fillOutput(enrichRuntime(se.SyscallCtxRaw.Task.CgroupID))

	// output msg
	msgByte, _ := json.Marshal(se.OutputMsg)
	msgByte = append(msgByte, []byte("\n")...)
	_, _ = se.Output.Write(msgByte)
}

func (se SyscallEvent) fillOutput(out *map[string]interface{}) {
	if out == nil {
		return
	}
	for k, v := range *out {
		se.OutputMsg[k] = v
	}
}

func init() {
	// init syscall buffer handler
	SyscallHandlerMap[unix.SYS_EXECVE] = fillExecve

	// set boot time
	file, err := os.Open("/proc/stat")
	if err != nil {
		return
	}
	defer file.Close()
	s := bufio.NewScanner(file)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if !strings.HasPrefix(s.Text(), "btime") {
			continue
		}
		if len(fields) < 2 {
			continue
		}
		bootTime, _ = strconv.ParseUint(fields[1], 10, 64)
	}
}
