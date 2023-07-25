package event

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	BuffSize   = 38*64 + 1
	TaskLen16  = 16
	TaskLen64  = 64
	MaxBufSize = 1024 * 4
)

// basic data types define

type (
	Domain [128]byte
	IP     uint32
	Port   uint16
	// Command process commandline
	Command  [64]byte
	Filename [64]byte

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
	TaskContext struct {
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
		Stdin     [TaskLen64]byte
		Stdout    [TaskLen64]byte
		Flag      uint32
	}

	SyscallContext struct {
		Timestamp   uint64
		Task        TaskContext
		Syscall     uint32
		ProcessorID uint16
		Argnum      uint32
	}

	Buffer struct {
		argNum     uint32
		bufferSize uint32
		buffer     []byte
	}
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

func (fn *Filename) string() string {
	//return string(bytes.Split(fn[:], []byte("\x00"))[0])
	return unix.ByteSliceToString(fn[:])
}

func (b *Buffer) string() map[int]string {
	// buf:[(u8)elem_num_1][(u32)str1_size][str1][(u32)str2_size][str2][(u8)elem_num_2][(u32)str1_size][str1]
	var (
		offset uint32 = 0
		args          = make(map[uint32][]string)
		ret           = make(map[int]string)
	)
	for index := uint32(0); index < b.argNum; index++ {
		var num = b.buffer[offset]
		offset += 1
		for i := uint8(0); offset < b.bufferSize && i < num; i++ {
			size := binary.LittleEndian.Uint32(b.buffer[offset : offset+4])
			offset += 4
			s := b.buffer[offset : offset+size]
			offset += size
			args[index] = append(args[index], string(bytes.ReplaceAll(s[:], []byte("\x00"), []byte(" "))))
		}
		ret[int(index)] = strings.TrimSpace(strings.Join(args[index], ""))
	}
	return ret
}
