package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mehmettopcu/goslo.policy.server/server"
)

func main() {
	policyDir := flag.String("policy-dir", "policy-rules", "Directory containing policy YAML files")
	logDir := flag.String("log-dir", "logs", "Directory containing policy YAML files")
	addr := flag.String("addr", ":8082", "Server address to listen on")
	flag.Parse()

	// Create policy directory if it doesn't exist
	if err := os.MkdirAll(*policyDir, 0755); err != nil {
		log.Fatalf("Failed to create policy directory: %v", err)
	}

	// Create and start policy manager
	pm, err := server.NewPolicyManager(*policyDir, *logDir)
	if err != nil {
		log.Fatalf("Failed to create policy manager: %v", err)
	}

	// Create context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal: %v", sig)
		cancel()
	}()

	log.Printf("Starting policy server on %s", *addr)
	if err := pm.StartServerWithContext(ctx, *addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	// Shutdown manager
	pm.Shutdown()
}
