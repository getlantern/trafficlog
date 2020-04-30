package tlhttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultScheme is the scheme used by Clients when Client.Scheme is not specified.
const DefaultScheme = "http"

// ClientSideError is an error that occurs on the client-side. This may be an error in building the
// request or in communicating over the network.
type ClientSideError struct {
	error
}

// Unwrap allows for Go 1.13-style error unwrapping.
func (e ClientSideError) Unwrap() error {
	return e.error
}

// Client for communicating with a traffic log over HTTP.
type Client struct {
	HTTPClient    http.Client
	ServerAddress string

	// Scheme should be either 'http' or 'https'. Defaults to DefaultScheme.
	Scheme string
}

// UpdateAddresses calls the corresponding method on the server's traffic log.
func (c Client) UpdateAddresses(addresses []string) error {
	return c.do(actionUpdateAddresses, requestUpdateAddresses{addresses}, nil)
}

// UpdateBufferSizes calls the corresponding method on the server's traffic log.
func (c Client) UpdateBufferSizes(captureBytes, saveBytes int) error {
	return c.do(actionUpdateBufferSizes, requestUpdateBufferSizes{captureBytes, saveBytes}, nil)
}

// SaveCaptures calls the corresponding method on the server's traffic log.
func (c Client) SaveCaptures(address string, d time.Duration) error {
	df := durationField(d)
	return c.do(actionSaveCaptures, requestSaveCaptures{address, &df}, nil)
}

// WritePcapng calls the corresponding method on the server's traffic log.
func (c Client) WritePcapng(w io.Writer) error {
	resp := new(responseGetCaptures)
	if err := c.do(actionGetCaptures, nil, resp); err != nil {
		return err
	}
	if _, err := w.Write(resp.Pcapng); err != nil {
		return fmt.Errorf("failed to write server response to input writer: %w", err)
	}
	return nil
}

// CheckHealth makes a test request to check the health of the server and the client's ability to
// connect to the server.
func (c Client) CheckHealth() error {
	return c.do(actionCheckHealth, nil, nil)
}

func (c Client) scheme() string {
	if c.Scheme == "" {
		return DefaultScheme
	}
	return c.Scheme
}

func (c Client) do(a action, reqBody interface{}, respBody interface{}) error {
	bodyReader := io.ReadWriter(nil)
	if reqBody != nil {
		bodyReader = new(bytes.Buffer)
		if err := json.NewEncoder(bodyReader).Encode(reqBody); err != nil {
			return ClientSideError{fmt.Errorf("failed to encode body: %w", err)}
		}
	}
	fullURL := fmt.Sprintf("%s://%s:%s", c.scheme(), c.ServerAddress, a.path)
	req, err := http.NewRequest(a.method, fullURL, bodyReader)
	if err != nil {
		return ClientSideError{fmt.Errorf("failed to build request: %w", err)}
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return ClientSideError{fmt.Errorf("failed to send request: %w", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != a.successCode {
		er := new(errorResponse)
		if err := json.NewDecoder(resp.Body).Decode(er); err != nil {
			return fmt.Errorf("got error status '%v', but failed to decode: %w", resp.Status, err)
		}
		return errors.New(er.ErrorMsg)
	}
	if respBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return ClientSideError{fmt.Errorf("failed to decode response: %w", err)}
		}
	}
	return nil
}
