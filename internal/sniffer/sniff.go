package sniffer

import (
	"fmt"

	"crypto/x509"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

// Sniffer represents the TLS monitoring server
type Sniffer struct {
	Port             int
	handle           *pcap.Handle
	CertificatesChan chan *x509.Certificate
}

// New creates a new Sniffer instance
func New(port int) *Sniffer {
	return &Sniffer{
		Port:             port,
		CertificatesChan: make(chan *x509.Certificate, 100),
	}
}

// Start begins monitoring TLS traffic
func (s *Sniffer) Start() error {
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

func (s *Sniffer) capture() {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())

	// Create TCP stream assembler
	streamFactory := &tlsStreamFactory{server: s}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	for packet := range packetSource.Packets() {
		// Get TCP layer
		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if !ok {
			continue
		}

		// Pass the TCP packets to the assembler
		assembler.AssembleWithTimestamp(
			packet.NetworkLayer().NetworkFlow(),
			tcp,
			packet.Metadata().Timestamp)
	}
}

type tlsStreamFactory struct {
	server *Sniffer
}

type tlsStream struct {
	net, transport gopacket.Flow
	bytes          []byte
	server         *Sniffer
}

func (f *tlsStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	stream := &tlsStream{
		net:       net,
		transport: transport,
		bytes:     []byte{},
		server:    f.server,
	}
	return stream
}

func (s *tlsStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, reassembly := range reassemblies {
		s.bytes = append(s.bytes, reassembly.Bytes...)

		for len(s.bytes) >= 5 {
			if s.bytes[0] == 22 && // Handshake
				s.bytes[1] == 3 && // TLS version major
				(s.bytes[2] == 1 || s.bytes[2] == 3) { // TLS version minor

				recordLen := int(s.bytes[3])<<8 | int(s.bytes[4])

				if len(s.bytes) >= 5+recordLen {
					if s.bytes[5] == 11 { // Certificate message
						// Skip record header (5) + handshake type (1) + handshake length (3)
						certListStart := 9

						if len(s.bytes) < certListStart+3 {
							s.bytes = s.bytes[1:]
							continue
						}

						// Get first certificate length
						certStart := certListStart + 3
						if len(s.bytes) < certStart+3 {
							s.bytes = s.bytes[1:]
							continue
						}

						certLen := int(s.bytes[certStart])<<16 |
							int(s.bytes[certStart+1])<<8 |
							int(s.bytes[certStart+2])

						// Sanity check the lengths
						if certLen <= 0 || certLen > 10000 { // Most certs are < 10KB
							s.bytes = s.bytes[1:]
							continue
						}

						certData := s.bytes[certStart+3 : certStart+3+certLen]
						cert, err := x509.ParseCertificate(certData)
						if err != nil {
							fmt.Printf("Error parsing certificate: %v\n", err)
							s.bytes = s.bytes[1:]
							continue
						}

						s.server.CertificatesChan <- cert
						return
					}
				}
			}
			s.bytes = s.bytes[1:]
		}
	}
}

func (s *tlsStream) ReassemblyComplete() {
	// Do nothing
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Stop stops the monitoring
func (s *Sniffer) Stop() error {
	if s.handle != nil {
		s.handle.Close()
	}
	return nil
}
