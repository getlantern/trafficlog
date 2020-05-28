package trafficlog

import (
	"bytes"
	"encoding/json"
	"math"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/trafficlog/tltest"
	"github.com/stretchr/testify/require"
)

// testTrafficLog adapts TrafficLog to fit the tltest.TrafficLog interface.
type testTrafficLog struct {
	*TrafficLog
}

func (ttl testTrafficLog) SaveCaptures(address string, d time.Duration) error {
	ttl.TrafficLog.SaveCaptures(address, d)
	return nil
}

func (ttl testTrafficLog) UpdateBufferSizes(captureBytes, saveBytes int) error {
	ttl.TrafficLog.UpdateBufferSizes(captureBytes, saveBytes)
	return nil
}

func TestTrafficLog(t *testing.T) {
	// Make the buffers large enough that we will not lose any packets.
	const captureBufferSize, saveBufferSize = 1024 * 1024, 1024 * 1024

	tl := New(captureBufferSize, saveBufferSize, nil)
	tltest.TestTrafficLog(t, testTrafficLog{tl})
}

func TestStatsTracker(t *testing.T) {
	t.Parallel()

	const (
		channels          = 10
		sendsPerChannel   = 5
		receivedPerSend   = uint64(10)
		droppedPerSend    = uint64(3)
		sleepBetweenSends = 10 * time.Millisecond
		updateInterval    = time.Hour // doesn't matter for this test
	)

	st := newStatsTracker(updateInterval)
	st.output = make(chan CaptureStats, channels*sendsPerChannel)

	wg := new(sync.WaitGroup)
	for i := 0; i < channels; i++ {
		c := make(chan CaptureStats)
		wg.Add(2)
		go func() {
			defer wg.Done()

			var received, dropped uint64
			for s := 0; s < sendsPerChannel; s++ {
				received = received + receivedPerSend
				dropped = dropped + droppedPerSend
				c <- CaptureStats{received, dropped}
			}
			close(c)
		}()
		go func() { st.track(c); wg.Done() }()
	}
	wg.Wait()
	st.close()

	var received, dropped uint64
	for stats := range st.output {
		received, dropped = stats.Received, stats.Dropped
	}
	require.Equal(t, received, channels*sendsPerChannel*receivedPerSend)
	require.Equal(t, dropped, channels*sendsPerChannel*droppedPerSend)
}

// TestPacketOverhead checks that the packet overhead value is still accurate.
func TestPacketOverhead(t *testing.T) {
	if !tltest.RunElevated {
		t.SkipNow()
	}

	type oppOutput struct {
		MeanPacketOverhead        float64
		OverheadStandardDeviation float64
	}

	cmdOutput, err := exec.Command("go", "run", "./internal/opp/main.go").Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Fatal(string(exitErr.Stderr))
		} else {
			t.Fatal(err)
		}
	}

	var parsedOutput oppOutput
	require.NoError(t, json.Unmarshal(cmdOutput, &parsedOutput))
	require.Less(
		t, parsedOutput.OverheadStandardDeviation/parsedOutput.MeanPacketOverhead, 0.1,
		"Standard deviation was too large for an accurate test. Mean overhead: %f; standard deviation: %f",
		parsedOutput.MeanPacketOverhead, parsedOutput.OverheadStandardDeviation,
	)
	require.Less(
		t, math.Abs(parsedOutput.MeanPacketOverhead-float64(overheadPerPacket))/parsedOutput.MeanPacketOverhead, 0.1,
		"Overhead-per-packet is not accurate. Actual: %f; configured: %d",
		parsedOutput.MeanPacketOverhead, overheadPerPacket,
	)
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
