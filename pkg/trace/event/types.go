package event

import (
	"bytes"
	"encoding/binary"
	"net"

	"golang.org/x/sys/unix"
)

const BuffSize = 128

// basic data types define

type (
	Domain [128]byte
	IP     uint32
	Port   uint16
	// Command process commandline
	Command  [64]byte
	Filename [128]byte
	Argv     [128]byte
	Envp     [128]byte
	// BufArrStr [string count][str1 size][str1][str2 size][str2]...
	BufArrStr struct {
		offsite uint32
		buffer  [BuffSize]byte
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

func (argv *Argv) string() string {
	return unix.ByteSliceToString(argv[:])
}

func (envp *Envp) string() string {
	return unix.ByteSliceToString(envp[:])
}
