package proc

import (
	"tulkun/pkg/cgroups"
	"tulkun/pkg/runtime"

	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/shirou/gopsutil/v3/process"
	log "github.com/sirupsen/logrus"
)

type Process struct {
	PID        int32
	PPID       int32
	Cmdline    string
	CgroupPath string
	Cgroup     *cgroup2.Manager
	Runtime    runtime.ContainersInterface
}

func NewProcess(pid int32) *Process {
	var p Process
	p.PID = pid
	proc, err := process.NewProcess(pid)
	if err != nil {
		log.Errorf("fetch new process PID %d error `%s` ", pid, err)
		return &p
	}
	p.PPID, _ = proc.Ppid()
	p.Cmdline, _ = proc.Cmdline()
	p.CgroupPath = cgroups.Cgroup2PathFromPID(int(pid))
	p.Cgroup = cgroups.LoadCgroup2FromPath(p.CgroupPath)
	p.Runtime = runtime.SelectContainerRuntime(p.CgroupPath)
	return &p
}

func (p *Process) InspectContainer() *runtime.ContainerMeta {
	return p.Runtime.InspectContainerWithCgroup(p.CgroupPath)
}
