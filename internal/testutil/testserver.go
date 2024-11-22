package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"time"
)

// TestServer represents a TLS server for testing
type TestServer struct {
	Server      *http.Server
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	Port        int
}

func GetRandomPort() (int, error) {
	listener, err := net.Listen("tcp", ":0")

	if err != nil {
		return 0, fmt.Errorf("failed to get random port: %w", err)
	}
	defer listener.Close()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("failed to get TCP address")
	}

	return addr.Port, nil
}

func NewTestServerWithRandomPort() (*TestServer, error) {
	port, err := GetRandomPort()
	if err != nil {
		return nil, err
	}
	return NewTestServer(port)
}

// NewTestServer creates a new TLS test server
func NewTestServer(port int) (*TestServer, error) {
	// Generate test certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Corp"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12, // Force TLS 1.2
	}

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		}),
	}

	return &TestServer{
		Server:      server,
		Certificate: cert,
		PrivateKey:  priv,
		Port:        port,
	}, nil
}

// Start starts the test server
func (s *TestServer) Start(ready chan<- struct{}) error {
	listener, err := net.Listen("tcp", s.Server.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	// Signal that we're ready to accept connections
	ready <- struct{}{}

	// Start serving TLS connections
	return s.Server.ServeTLS(listener, "", "")
}

// Stop stops the test server
func (ts *TestServer) Stop() error {
	return ts.Server.Close()
}
