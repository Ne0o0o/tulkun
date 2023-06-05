package tulkun

import (
	_ "embed"
)

//go:embed "dist/tulkun.bpf.o"
var BPFObjectBuffer []byte

//go:embed "version.txt"
var Version string
