package main

import (
	"flag"
	"log"
)

func main() {
	// Command line flags
	port := flag.Int("port", 0, "Port to monitor for TLS traffic")
	flag.Parse()

	if *port == 0 {
		log.Fatal("Port must be specified")
	}

	// TODO: Initialize monitoring
}
