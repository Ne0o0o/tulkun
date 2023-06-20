package Container

import (
	"os"

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

type ContainersInterface interface {
	Version() string
}

type ContainersClient struct {
	CurrentClient ContainersInterface
	Version       string
	runtimeSock   map[string]string
}

func (cli *ContainersClient) register(name string, unixSocket string, register func(string) (ContainersInterface, error)) {
	if _, err := os.Stat(unixSocket); err != nil {
		log.Errorf("get runtime client `%s` socket error `%s`", name, unixSocket)
		return
	}

	cli.runtimeSock[name] = unixSocket

	if cli.CurrentClient == nil {
		client, err := register(unixSocket)
		if err != nil {
			log.Errorf("create runtime client `%s` error `%s`", name, err)
			return
		}
		cli.CurrentClient = client
	}
}

var Client = &ContainersClient{
	runtimeSock: make(map[string]string),
}

func init() {
	Client.register(Crio, defaultCrioSock, NewCrioClient)
	Client.register(Docker, defaultDockerSock, NewDockerClient)
}
