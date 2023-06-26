package cgroups

import (
	"github.com/containerd/cgroups/v3/cgroup2"
	log "github.com/sirupsen/logrus"
)

func Cgroup2PathFromPID(pid int) string {
	cgroupPath, err := cgroup2.PidGroupPath(pid)
	if err != nil {
		log.Errorf("fetch new process PID %d cgroup error `%s` ", pid, err)
		return ""
	}
	return cgroupPath
}

func LoadCgroup2FromPath(cgroupPath string) *cgroup2.Manager {
	mgr, err := cgroup2.LoadSystemd("/", cgroupPath)
	if err != nil {
		log.Errorf("fetch cgroup path %s error `%s` ", cgroupPath, err)
		return nil
	}
	return mgr
}

func LoadCgroup2FromPID(pid int) *cgroup2.Manager {
	cgroupPath, err := cgroup2.PidGroupPath(pid)
	if err != nil {
		log.Errorf("fetch new process PID %d cgroup error `%s` ", pid, err)
		return nil
	}

	mgr, err := cgroup2.LoadSystemd("/", cgroupPath)
	if err != nil {
		log.Errorf("fetch new process PID %d cgroup error `%s` ", pid, err)
		return nil
	}
	return mgr
}
