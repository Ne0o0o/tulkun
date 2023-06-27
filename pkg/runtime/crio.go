package runtime

import (
	"context"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type crioClient struct {
	client   cri.RuntimeServiceClient
	socketFD string
}

func (cli *crioClient) InspectContainerWithCgroup(cgroup string) *ContainerMeta {
	//TODO implement me
	panic("implement me")
}

func NewCrioClient(socket string) (ContainersInterface, error) {
	unixSocket := "unix://" + strings.TrimPrefix(socket, "unix://")
	conn, err := grpc.Dial(unixSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &crioClient{client: cri.NewRuntimeServiceClient(conn), socketFD: unixSocket}, err
}

func (cli *crioClient) Version() string {
	resp, err := cli.client.Version(context.Background(), &cri.VersionRequest{})
	if err != nil {
		log.Errorf("version error `%s`", err)
		return ""
	}
	return resp.String()
}

func (cli *crioClient) ListContainers() {
	_, err := cli.client.ListContainers(context.Background(), &cri.ListContainersRequest{})
	if err != nil {
		log.Errorf("list containers error `%s`", err)
		return
	}
}

func (cli *crioClient) InspectContainer(containerID string) {
	_, err := cli.client.ContainerStats(context.Background(), &cri.ContainerStatsRequest{
		ContainerId: containerID,
	})
	if err != nil {
		log.Errorf("get container inspect error `%s`", err)
		return
	}
}
