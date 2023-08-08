package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"tulkun"
	"tulkun/pkg/trace"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func main() {
	app := cli.App{
		Name:           "Tulkun",
		HelpName:       "eBPF based lightweight Host-based Intrusion Detection Tools",
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
				Usage:   "select network interface for network traffic monitor",
				Value:   "",
				Aliases: []string{"i"},
			},
			&cli.StringFlag{
				Name:  "bpf-object",
				Usage: "load custom bpf object",
			},
		},
		EnableBashCompletion: false,
		BashComplete:         nil,
		Before:               nil,
		After:                nil,
		Action: func(c *cli.Context) error {
			var (
				bpfObjectBuffer []byte
				err             error
			)
			// load bpf object from custom file
			if file := c.String("bpf-object"); file != "" {
				if bpfObjectBuffer, err = os.ReadFile(file); err != nil {
					return err
				}
			} else {
				bpfObjectBuffer = tulkun.BPFObjectBuffer
			}

			//  init new tracker
			collections, err := trace.NewTracker(bpfObjectBuffer)
			if err != nil {
				log.Fatalf("load ebpf object error %s ", err)
			}

			ctx, cancel := context.WithCancelCause(context.Background())
			collections.RunWithCancel(ctx)
			defer collections.Destroy()
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
