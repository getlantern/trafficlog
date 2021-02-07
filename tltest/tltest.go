// Package tltest is used to test traffic logs.
package tltest

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The time we allow for capture to start or take place.
const captureWaitTime = 200 * time.Millisecond

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

	defer tl.Close()
	if !*runElevatedFlag {
		t.SkipNow()
	}

	const (
		captureAddresses     = 10
		serverResponseString = "TestTrafficLog test server response"

		// Make the buffers large enough that we will not lose any packets.
		captureBufferSize, saveBufferSize = 1024 * 1024, 1024 * 1024
	)

	responseFor := func(serverNumber int) string {
		return fmt.Sprintf("<%s - server number %d>", serverResponseString, serverNumber)
	}

	makeServers := func(n, start int) (addresses []string) {
		addresses = make([]string, n)
		for i := 0; i < n; i++ {
			resp := responseFor(i + start)
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintln(w, resp)
			}))
			t.Cleanup(s.Close)
			addresses[i] = strings.Replace(s.URL, "http://", "", -1)
		}
		return addresses
	}

	addresses := makeServers(captureAddresses, 0)
	require.NoError(t, tl.UpdateAddresses(addresses))

	go func() {
		for err := range tl.Errors() {
			t.Log(err)
			t.Fail()
			return
		}
	}()

	time.Sleep(captureWaitTime)
	for _, a := range addresses {
		_, err := http.Get("http://" + a)
		require.NoError(t, err)
	}

	time.Sleep(captureWaitTime)
	for i, addr := range addresses {
		// Ensure that we can filter by address by only capturing for even servers.
		if i%2 == 0 {
			require.NoError(t, tl.SaveCaptures(addr, time.Minute))
		}
	}

	pcapFileBuf := new(bytes.Buffer)
	require.NoError(t, tl.WritePcapng(pcapFileBuf))

	pcapFile := pcapFileBuf.String()
	for i := 0; i < captureAddresses; i++ {
		switch i % 2 {
		case 0:
			requireContainsOnce(t, pcapFile, responseFor(i))
		default:
			requireNotContains(t, pcapFile, responseFor(i))
		}
	}

	// Ensure that we can filter by time.
	clearSaveBuffer(t, tl, addresses, captureBufferSize, saveBufferSize)
	pcapFileBuf.Reset()
	resetTime := time.Now()

	newAddresses := makeServers(captureAddresses, len(addresses))
	require.NoError(t, tl.UpdateAddresses(concat(addresses, newAddresses)))

	time.Sleep(captureWaitTime)
	for _, a := range newAddresses {
		_, err := http.Get("http://" + a)
		require.NoError(t, err)
	}

	time.Sleep(captureWaitTime)
	for _, addr := range concat(addresses, newAddresses) {
		require.NoError(t, tl.SaveCaptures(addr, time.Since(resetTime)))
	}

	require.NoError(t, tl.WritePcapng(pcapFileBuf))
	pcapFile = pcapFileBuf.String()
	for i := 0; i < len(addresses); i++ {
		requireNotContains(t, pcapFile, responseFor(i))
	}
	for i := len(addresses); i < len(addresses)+len(newAddresses); i++ {
		require.Contains(t, pcapFile, responseFor(i))
	}
}

// As a side effect, there will be a single packet in the save buffer. This packet will be to or
// from an address reserved until the end of the test, so it should not interfere with testing.
func clearSaveBuffer(t *testing.T, tl TrafficLog, addresses []string, captureBufferSize, saveBufferSize int) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })

	require.NoError(t, tl.UpdateAddresses(append([]string{l.Addr().String()}, addresses...)))
	defer func() { require.NoError(t, tl.UpdateAddresses(addresses)) }()

	conn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	conn.Close()

	time.Sleep(captureWaitTime)

	require.NoError(t, tl.UpdateBufferSizes(captureBufferSize, 0))
	require.NoError(t, tl.SaveCaptures(l.Addr().String(), time.Hour)) // flush the change
	require.NoError(t, tl.UpdateBufferSizes(captureBufferSize, saveBufferSize))

	// Sanity check by writing out captured packets - we should see a single packet from our earlier
	// TCP connection.
	buf := new(bytes.Buffer)
	require.NoError(t, tl.WritePcapng(buf))
	pcapReader, err := pcapgo.NewNgReader(buf, pcapgo.NgReaderOptions{WantMixedLinkType: true})
	require.NoError(t, err)
	_, _, err = pcapReader.ReadPacketData()
	require.NoError(t, err)
	_, _, err = pcapReader.ReadPacketData()
	require.True(t, errors.Is(err, io.EOF), "error type: %T; msg: %v", err, err)
}

func requireContainsOnce(t *testing.T, s, substring string) {
	t.Helper()

	b, subslice := []byte(s), []byte(substring)
	idx := bytes.Index(b, subslice)
	if idx < 0 {
		fail(t, "substring '%s' does not appear", substring)
	}
	if bytes.Index(b[idx+len(subslice):], subslice) > 0 {
		fail(t, "substring '%s' appears more than once", substring)
	}
}

// testify/require has a similar function, but the output is a little messy in our case.
func requireNotContains(t *testing.T, s, substring string) {
	t.Helper()

	if strings.Contains(s, substring) {
		fail(t, "substring '%s' should not appear", substring)
	}
}

func fail(t *testing.T, msg string, args ...interface{}) {
	t.Helper()
	callerInfo := new(bytes.Buffer)
	for _, entry := range assert.CallerInfo()[1:] {
		fmt.Fprintf(callerInfo, "\n\t\t%s", entry)
	}
	t.Fatalf("\n\t%s\n\ttrace:%s", fmt.Sprintf(msg, args...), callerInfo.String())
}

func concat(s1, s2 []string) []string {
	res := make([]string, len(s1)+len(s2))
	copy(res, s1)
	copy(res[len(s1):], s2)
	return res
}
