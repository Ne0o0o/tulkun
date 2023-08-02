package event

const (
	argv = iota
	envp
)

var syscallArgs = map[int]string{
	argv: "argv",
	envp: "envp",
}

func fillExecve(buf SyscallBuffer) *map[string]interface{} {
	var Message = make(map[string]interface{})
	buffer := buf.string()
	Message[syscallArgs[argv]] = buffer[argv]
	Message[syscallArgs[envp]] = buffer[envp]
	return &Message
}
