package runtime

import (
	"context"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
)

type dockerClient struct {
	client   *docker.Client
	socketFD string
}

func NewDockerClient(socket string) (ContainersInterface, error) {
	unixSocket := "unix://" + strings.TrimPrefix(socket, "unix://")
	client, err := docker.NewClientWithOpts(docker.WithHost(unixSocket), docker.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &dockerClient{client: client, socketFD: unixSocket}, nil
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

func (cli *dockerClient) InspectContainerWithID(containerID string) *ContainerMeta {
	container, err := cli.client.ContainerInspect(context.Background(), containerID)
	if err != nil {
		log.Errorf("get container `%s` inspect error `%s`", containerID, err)
		return nil
	}
	image, _, err := cli.client.ImageInspectWithRaw(context.Background(), container.Image)
	if err != nil {
		return nil
	}

	return &ContainerMeta{
		ContainerId: container.ID,
		Name:        container.Name,
		ImageID:     container.Image,
		ImageName:   image.RepoTags[0],
	}
}

func (cli *dockerClient) InspectContainerWithCgroup(cgroup string) *ContainerMeta {
	// hack tricks
	// /sys/fs/cgroup/system.slice/docker-94f6e438b02e8370c4de5b98caeae7b974b93c15182b8919ed3bddd3b95de15b.scope#
	r, err := regexp.Compile(`docker-(.*?)\.scope`)
	if err != nil {
		return nil
	}
	ret := r.FindAllStringSubmatch(cgroup, -1)
	if len(ret) != 0 {
		if len(ret[0]) == 2 {
			return cli.InspectContainerWithID(ret[0][1])
		}
	}
	return nil
}
