package server

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// CertificateInfo stores information about observed certificates
type CertificateInfo struct {
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	SerialNumber string
}

// Server represents the TLS monitoring server
type Server struct {
	Port             int
	handle           *pcap.Handle
	CertificatesChan chan CertificateInfo
}

// New creates a new Server instance
func New(port int) *Server {
	return &Server{
		Port:             port,
		CertificatesChan: make(chan CertificateInfo, 100),
	}
}

// Start begins monitoring TLS traffic
func (s *Server) Start() error {
	// Open device for capturing
	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening device: %v", err)
	}
	s.handle = handle

	// Set filter for TLS traffic on specified port
	filter := fmt.Sprintf("tcp port %d", s.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("error setting BPF filter: %v", err)
	}

	go s.capture()
	return nil
}

func (s *Server) capture() {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	for packet := range packetSource.Packets() {
		packet.Data()
	}
}

// Stop stops the monitoring
func (s *Server) Stop() error {
	if s.handle != nil {
		s.handle.Close()
	}
	return nil
}
