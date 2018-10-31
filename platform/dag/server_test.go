package dag

import (
	"testing"
	"time"
)

func TestStartAndStop(t *testing.T) {
	server := NewRPCServer(nil, nil)

	server.Start()

	time.Sleep(time.Second * 24)

	server.Stop()
}
