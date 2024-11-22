package sniffer_test

import (
	"fmt"
	"testing"
	"time"

	"tlssniffer/internal/sniffer"
	"tlssniffer/internal/testutil"
)

func TestTLSHandshakeCapture(t *testing.T) {
	// Create and start test server
	testServer, err := testutil.NewTestServerWithRandomPort()
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	ready := make(chan struct{})
	go func() {
		if err := testServer.Start(ready); err != nil {
			t.Errorf("Test server error: %v", err)
		}
	}()

	// Wait for server to be ready
	select {
	case <-ready:
		// Server is ready
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for server to start")
	}

	// Create and start the TLS sniffer
	sniffer := sniffer.New(testServer.Port)
	if err := sniffer.Start(); err != nil {
		t.Fatalf("Failed to start sniffer: %v", err)
	}
	defer sniffer.Stop()

	// Create and connect test client
	testClient := testutil.NewTestClient()
	if err := testClient.Connect(fmt.Sprintf("localhost:%d", testServer.Port)); err != nil {
		t.Fatalf("Failed to connect test server: %v", err)
	}

	// Wait for certificate information
	select {
	case certInfo := <-sniffer.CertificatesChan:
		// Verify certificate details
		if certInfo.Organization != "Test Corp" {
			t.Errorf("Unexpected subject: got %s, want O=Test Corp", certInfo.Organization)
		}
		// Add more certificate checks as needed
	case <-time.After(5 * time.Minute):
		t.Fatal("Timeout waiting for certificate information")
	}
}
