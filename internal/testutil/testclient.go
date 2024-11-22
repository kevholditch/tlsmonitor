package testutil

import (
	"crypto/tls"
	"net/http"
)

// TestClient represents a TLS client for testing
type TestClient struct {
	client *http.Client
}

// NewTestClient creates a new TLS test client
func NewTestClient() *TestClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skip verification for test certificates
		},
	}

	client := &http.Client{
		Transport: transport,
	}

	return &TestClient{
		client: client,
	}
}

// Connect makes a TLS connection to the specified address
func (tc *TestClient) Connect(addr string) error {
	resp, err := tc.client.Get("https://" + addr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
