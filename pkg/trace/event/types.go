package event

import (
	"bytes"
	"encoding/binary"
	"net"

	"golang.org/x/sys/unix"
)

const BuffSize = 38*64 + 1

// basic data types define

type (
	Domain [128]byte
	IP     uint32
	Port   uint16
	// Command process commandline
	Command  [64]byte
	Filename [64]byte

	// BufArrStr [string count][str1 size][str1][str2 size][str2]...
	BufArrayStr struct {
		offset uint32
		buffer [BuffSize]byte
	}
	Process struct {
		PID  uint32
		UID  uint32
		GID  uint32
		TGID uint32
		TTY  [64]byte
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

func (ar *BufArrayStr) stringArray() (ret []string) {
	// buf: [(u8)string count][(u32)str1 size][str1][(u32)str2 size][str2]...
	var (
		length        = ar.offset
		offset uint32 = 1
		i             = 0
		num           = int(ar.buffer[0])
	)
	for offset < length && i < num {
		size := binary.LittleEndian.Uint32(ar.buffer[offset : offset+4])
		offset += 4
		s := ar.buffer[offset : offset+size]
		offset += size
		ret = append(ret, string(s))
	}
	return
}
