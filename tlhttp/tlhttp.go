// Package tlhttp implements constructs for communicating with a traffic log over HTTP
package tlhttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/getlantern/trafficlog"
)

type action struct {
	path, method string
	successCode  int
}

var (
	actionUpdateAddresses   = action{"/addresses", "PUT", http.StatusNoContent}
	actionUpdateBufferSizes = action{"/buffer-sizes", "PUT", http.StatusNoContent}
	actionSaveCaptures      = action{"/save-captures", "POST", http.StatusNoContent}
	actionGetCaptures       = action{"/captures", "GET", http.StatusOK}
	actionCheckHealth       = action{"/health", "GET", http.StatusNoContent}
)

type errorResponse struct {
	ErrorMsg string
}

type httpError struct {
	error
	statusCode int
}

func httpErrorf(statusCode int, msg string, a ...interface{}) *httpError {
	return &httpError{fmt.Errorf(msg, a...), statusCode}
}

// A body is only returned if there was no error. Otherwise, the error is used to create a body.
type httpHandleFunc func(http.ResponseWriter, *http.Request) (body interface{}, err *httpError)

type trafficLogMux struct {
	*trafficlog.TrafficLog
	*http.ServeMux
	errorLog io.Writer
}

// RequestHandler creates a request multiplexer using the input traffic log. If an error log is
// provided, then any 5xx or similar errors encountered by the handler will be logged.
func RequestHandler(tl *trafficlog.TrafficLog, errorLog io.Writer) http.Handler {
	if errorLog == nil {
		errorLog = ioutil.Discard
	}
	m := trafficLogMux{tl, http.NewServeMux(), errorLog}
	for _, e := range []struct {
		action
		handler httpHandleFunc
	}{
		{actionUpdateAddresses, m.updateAddresses},
		{actionUpdateBufferSizes, m.updateBufferSizes},
		{actionSaveCaptures, m.saveCaptures},
		{actionGetCaptures, m.getCaptures},
		{actionCheckHealth, m.checkHealth},
	} {
		m.handle(e.action, e.handler)
	}
	return m
}

func (m trafficLogMux) writeResponse(w io.Writer, resp interface{}) {
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		fmt.Fprintln(m.errorLog, "failed to encode response:", err)
	}
}

func (m trafficLogMux) handle(a action, handler httpHandleFunc) {
	m.HandleFunc(a.path, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != a.method {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := handler(w, req)
		if err != nil {
			w.WriteHeader(err.statusCode)
			m.writeResponse(w, errorResponse{err.Error()})
			if err.statusCode >= 500 {
				fmt.Fprintf(
					m.errorLog, "returning %v from %s %s: %v\n",
					http.StatusText(err.statusCode), a.path, a.method, err)
			}
			return
		}
		w.WriteHeader(a.successCode)
		if body != nil {
			m.writeResponse(w, body)
		}
	})
}

type requestUpdateAddresses struct {
	Addresses []string
}

func (m trafficLogMux) updateAddresses(w http.ResponseWriter, req *http.Request) (interface{}, *httpError) {
	reqBody := new(requestUpdateAddresses)
	if err := json.NewDecoder(req.Body).Decode(reqBody); err != nil {
		return nil, httpErrorf(http.StatusBadRequest, "failed to decode request: %w", err)
	}
	if err := m.UpdateAddresses(reqBody.Addresses); err != nil {
		if ok := errors.As(err, new(trafficlog.ErrorMalformedAddress)); ok {
			return nil, httpErrorf(http.StatusBadRequest, err.Error())
		}
		return nil, httpErrorf(http.StatusInternalServerError, err.Error())
	}
	return nil, nil
}

type requestUpdateBufferSizes struct {
	CaptureBytes, SaveBytes int
}

func (m trafficLogMux) updateBufferSizes(w http.ResponseWriter, req *http.Request) (interface{}, *httpError) {
	reqBody := new(requestUpdateBufferSizes)
	if err := json.NewDecoder(req.Body).Decode(reqBody); err != nil {
		return nil, httpErrorf(http.StatusBadRequest, "failed to decode request: %w", err)
	}
	m.UpdateBufferSizes(reqBody.CaptureBytes, reqBody.SaveBytes)
	return nil, nil
}

type requestSaveCaptures struct {
	Address  string
	Duration *durationField
}

func (r requestSaveCaptures) duration() time.Duration {
	if r.Duration == nil {
		return 0
	}
	return time.Duration(*r.Duration)
}

func (m trafficLogMux) saveCaptures(w http.ResponseWriter, req *http.Request) (interface{}, *httpError) {
	reqBody := new(requestSaveCaptures)
	if err := json.NewDecoder(req.Body).Decode(reqBody); err != nil {
		return nil, httpErrorf(http.StatusBadRequest, "failed to decode request: %w", err)
	}
	m.SaveCaptures(reqBody.Address, reqBody.duration())
	return nil, nil
}

type responseGetCaptures struct {
	Pcapng []byte
}

func (m trafficLogMux) getCaptures(w http.ResponseWriter, req *http.Request) (interface{}, *httpError) {
	buf := new(bytes.Buffer)
	if err := m.WritePcapng(buf); err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, err.Error())
	}
	return responseGetCaptures{buf.Bytes()}, nil
}

func (m trafficLogMux) checkHealth(w http.ResponseWriter, req *http.Request) (interface{}, *httpError) {
	return nil, nil
}

type durationField time.Duration

func (f *durationField) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(*f).String())
}

func (f *durationField) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	s := strings.TrimPrefix(strings.TrimSuffix(string(data), `"`), `"`)
	d, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*f = durationField(d)
	return nil
}
