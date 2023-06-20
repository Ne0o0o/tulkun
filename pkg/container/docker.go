package Container

import (
	"context"
	"strings"

	"github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
)

type dockerClient struct {
	client *docker.Client
}

func (cli *dockerClient) Version() string {
	return cli.client.ClientVersion()
}

func (cli *dockerClient) ListContainers() {
	_, err := cli.client.ContainerList(context.Background(), types.ContainerListOptions{All: true})
	if err != nil {
		log.Errorf("list containers error `%s`", err)
	}
}

func NewDockerClient(socket string) (ContainersInterface, error) {
	unixSocket := "unix://" + strings.TrimPrefix(socket, "unix://")
	client, err := docker.NewClientWithOpts(docker.WithHost(unixSocket), docker.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &dockerClient{client: client}, nil
}
