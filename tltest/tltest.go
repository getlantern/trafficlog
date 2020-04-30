// Package tltest is used to test traffic logs.
package tltest

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// RunElevated controls whether tests requiring elevated permissions are run. These tests are
// disabled by defaults. Set this variable to true to run these tests. Alternatively, use the flag
// from the command line (preceded by the -args flag).
var RunElevated = false

// runElevatedFlag is used to control whether tests requiring elevated permissions are run.
var runElevatedFlag = flag.Bool(
	"elevated",
	RunElevated,
	"run tests requiring elevated permissions",
)

// TrafficLog is the interface implemented by traffic logs.
type TrafficLog interface {
	UpdateAddresses([]string) error
	UpdateBufferSizes(int, int) error
	SaveCaptures(string, time.Duration) error
	WritePcapng(w io.Writer) error
	Close() error
	Errors() <-chan error
}

// TestTrafficLog tests a TrafficLog for correctness.
func TestTrafficLog(t *testing.T, tl TrafficLog) {
	t.Helper()
	t.Parallel()

	if !*runElevatedFlag {
		t.SkipNow()
	}

	const (
		captureAddresses     = 10
		serverResponseString = "TestTrafficLog test server response"

		// Make the buffers large enough that we will not lose any packets.
		captureBufferSize, saveBufferSize = 1024 * 1024, 1024 * 1024

		// The time we allow for capture to start or take place.
		captureWaitTime = 200 * time.Millisecond
	)

	responseFor := func(serverNumber int) string {
		return fmt.Sprintf("%s - server number %d", serverResponseString, serverNumber)
	}

	servers := make([]*httptest.Server, captureAddresses)
	addresses := make([]string, captureAddresses)
	for i := 0; i < captureAddresses; i++ {
		resp := responseFor(i)
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintln(w, resp)
		}))
		defer servers[i].Close()
		addresses[i] = strings.Replace(servers[i].URL, "http://", "", -1)
	}

	require.NoError(t, tl.UpdateAddresses(addresses))
	defer tl.Close()

	go func() {
		for err := range tl.Errors() {
			t.Log(err)
			t.Fail()
			return
		}
	}()

	time.Sleep(captureWaitTime)
	for _, s := range servers {
		_, err := http.Get(s.URL)
		require.NoError(t, err)
	}

	time.Sleep(captureWaitTime)
	for _, addr := range addresses {
		require.NoError(t, tl.SaveCaptures(addr, time.Minute))
	}

	pcapFileBuf := new(bytes.Buffer)
	require.NoError(t, tl.WritePcapng(pcapFileBuf))

	pcapFile := pcapFileBuf.String()
	for i := 0; i < captureAddresses; i++ {
		requireContainsOnce(t, pcapFile, responseFor(i))
	}
}

func requireContainsOnce(t *testing.T, s, substring string) {
	t.Helper()

	b, subslice := []byte(s), []byte(substring)
	idx := bytes.Index(b, subslice)
	if idx < 0 {
		t.Fatalf("subslice does not appear")
	}
	if bytes.Index(b[idx+len(subslice):], subslice) > 0 {
		t.Fatalf("subslice appears more than once")
	}
}
