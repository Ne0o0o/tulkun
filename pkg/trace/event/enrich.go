package event

import (
	"tulkun/pkg/cgroups"
	"tulkun/pkg/proc"
	"tulkun/pkg/runtime"
)

func enrichProcess(pid int32, msg map[string]interface{}) {
	if pid == 0 {
		return
	}

	p := proc.NewProcess(pid)
	msg["PPID"] = p.PPID
	msg["cmdline"] = p.Cmdline
	msg["cgroup"] = p.CgroupPath
	if p.Runtime != nil {
		if meta := p.InspectContainer(); meta != nil {
			msg["containerId"] = meta.ContainerId
			msg["containerName"] = meta.Name
			msg["imageId"] = meta.ImageID
			msg["imageName"] = meta.ImageName
		}
	}
}

func enrichRuntime(cgroupId uint64) *map[string]interface{} {
	cgroup := cgroups.Cgroup2PathFromInode(cgroupId)
	if cgroup == "" {
		return nil
	}
	var runtimeMeta = make(map[string]interface{})
	runtimeMeta["cgroup"] = cgroup
	if rt := runtime.SelectContainerRuntime(cgroup); rt != nil {
		if meta := rt.InspectContainerWithCgroup(cgroup); meta != nil {
			var container = make(map[string]interface{})
			container["containerId"] = meta.ContainerId
			container["containerName"] = meta.Name
			container["imageId"] = meta.ImageID
			container["imageName"] = meta.ImageName
			runtimeMeta["runtime"] = container
		}
	}
	return &runtimeMeta
}
