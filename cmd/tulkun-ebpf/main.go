package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"tulkun"
	"tulkun/pkg/tracker"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func main() {
	app := cli.App{
		Name:           "Tulkun",
		HelpName:       "eBPF based lightweight Host-based Intrusion Detection System",
		Usage:          "",
		UsageText:      "",
		ArgsUsage:      "",
		Version:        tulkun.Version,
		Description:    "",
		DefaultCommand: "",
		Commands:       nil,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "interface",
				Usage:   "select network interface for DNS monitor",
				Value:   "",
				Aliases: []string{"i"},
			},
		},
		EnableBashCompletion: false,
		BashComplete:         nil,
		Before:               nil,
		After:                nil,
		Action: func(c *cli.Context) error {
			ctx, cancel := context.WithCancelCause(context.Background())
			tracker.ProbeCollections.RunWithCancel(ctx)
			defer tracker.ProbeCollections.Destroy()
			func(causeFunc context.CancelCauseFunc) {
				c := make(chan os.Signal)
				signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
				for e := range c {
					cancel(errors.New(fmt.Sprintf("quit with signal `%s`", e.String())))
					return
				}
			}(cancel)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal("run tulkun error ", err)
	}
}
