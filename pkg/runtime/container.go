package runtime

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	defaultCrioSock   = "/var/run/crio/crio.sock"
	defaultDockerSock = "/var/run/docker.sock"
)

const (
	Crio   = "crio"
	Docker = "docker"
)

type ContainerMeta struct {
	ContainerId string
	Name        string
	ImageID     string
	ImageName   string
	// Pod         PodMetadata
}

type ContainersInterface interface {
	Version() string
	InspectContainerWithCgroup(cgroup string) *ContainerMeta
}

func SelectContainerRuntime(pid int, cgroup string) ContainersInterface {
	// docker
	if strings.Contains(cgroup, "docker") {
		if _, ok := socketCollection.opt[Docker]; ok {
			return socketCollection.opt[Docker]
		}
	}
	// TODO crio
	return nil
}

func register(name string, unixSocket string, register func(string) (ContainersInterface, error)) {
	if _, err := os.Stat(unixSocket); err != nil {
		log.Errorf("get runtime client `%s` socket error `%s`", name, unixSocket)
		return
	}
	sock, err := register(unixSocket)
	if err != nil {
		log.Errorf("get runtime client `%s` socket error `%s`", name, unixSocket)
	}
	socketCollection.socketFD = unixSocket
	socketCollection.opt[name] = sock
}

var socketCollection struct {
	opt      map[string]ContainersInterface
	socketFD string
}

func init() {
	socketCollection.opt = make(map[string]ContainersInterface)
	register(Crio, defaultCrioSock, NewCrioClient)
	register(Docker, defaultDockerSock, NewDockerClient)
}
