package fs

import (
	"encoding/json"
	"io"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

type Watcher struct {
	FSWatcher *fsnotify.Watcher
	Output    io.Writer
}

func NewWatcher(o io.Writer) (*Watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &Watcher{
		FSWatcher: w,
		Output:    o,
	}, nil
}

func (w *Watcher) Add(path string) {
	err := w.FSWatcher.Add(path)
	if err != nil {
		log.Error(err)
	}
}

func (w *Watcher) Listen() {
	for {
		select {
		case event, ok := <-w.FSWatcher.Events:
			if !ok {
				return
			}
			msg := make(map[string]string)
			switch event.Op {
			case fsnotify.Create:
				msg["op"] = "create"
			case fsnotify.Write:
				msg["op"] = "write"
			case fsnotify.Remove:
				msg["op"] = "remove"
			case fsnotify.Rename:
				msg["op"] = "rename"
			case fsnotify.Chmod:
				msg["op"] = "chmod"
			}
			msg["path"] = event.Name
			msgByte, err := json.Marshal(msg)
			if err != nil {
				return
			}
			_, _ = w.Output.Write(msgByte)
		case err, ok := <-w.FSWatcher.Errors:
			if !ok {
				return
			}
			log.Error(err)
		}
	}
}

func (w *Watcher) Destroy() {
	_ = w.FSWatcher.Close()
}
