package main

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/golang/glog"
)

func dumpJSON(format string, jsonData []byte) {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, jsonData, "", "  "); err == nil {
		glog.V(2).Infof(format, string(prettyJSON.Bytes()))
	}
}

func repeat(action func() error, delay time.Duration, doneC chan error) chan struct{} {
	stopC := make(chan struct{})

	go func() {
		for {
			if err := action(); err != nil {
				doneC <- err
				return
			}

			select {
			case <-time.After(delay):
				// Perform another iteration

			case <-stopC:
				doneC <- nil
				return
			}
		}
	}()

	return stopC
}
