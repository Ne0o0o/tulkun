package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"tulkun/pkg/tracker"
)

func main() {
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
}
