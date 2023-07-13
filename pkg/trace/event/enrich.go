package event

import (
	"tulkun/pkg/proc"
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
