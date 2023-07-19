package cgroups

import (
	"io/fs"
	"path/filepath"
	"syscall"

	"github.com/containerd/cgroups/v3/cgroup2"
	log "github.com/sirupsen/logrus"
)

const cgroupDefaultPath = "/sys/fs/cgroup"

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

func Cgroup2PathFromInode(inode uint64) string {
	var cgroupPath string
	err := filepath.WalkDir(cgroupDefaultPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				if stat.Ino == inode {
					cgroupPath = path
				}
			}
		}
		return nil
	})
	if err != nil {
		log.Errorf("fetch cgroup error `%s`", err)
	}
	return cgroupPath
}

func LoadCgroup2FromInode(inode int) *cgroup2.Manager {
	var cgroupPath string
	err := filepath.WalkDir(cgroupDefaultPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				if stat.Ino == uint64(inode) {
					cgroupPath = path
				}
			}
		}
		return nil
	})
	if err != nil || cgroupPath == "" {
		return nil
	}
	return LoadCgroup2FromPath(cgroupPath)
}
