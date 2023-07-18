package event

import "golang.org/x/sys/unix"

func (tc TaskContext) fill() *map[string]interface{} {
	/*
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
		TTY       [TaskCommLen]byte
		Comm      [TaskCommLen]byte
		UtsName   [TaskCommLen]byte
		Flag      uint32
	*/
	var task = make(map[string]interface{})
	task["st"] = tc.StartTime
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
	task["flag"] = tc.Flag
	return &task
}

func (sc SyscallContext) fill() *map[string]interface{} {
	var syscallCtx = make(map[string]interface{})
	syscallCtx["timestamp"] = sc.Timestamp
	syscallCtx["syscall"] = sc.Syscall
	syscallCtx["processorID"] = sc.ProcessorID
	syscallCtx["argnum"] = sc.Argnum
	syscallCtx["task"] = *sc.Task.fill()
	return &syscallCtx
}
