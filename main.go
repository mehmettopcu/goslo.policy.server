package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mehmettopcu/goslo.policy.server/log"
	"github.com/mehmettopcu/goslo.policy.server/server"
)

const (
	// Default values
	defaultPolicyDir = "policy-files"
	defaultLogDir    = "audit-logs"
	defaultAddr      = ":8082"

	// Timeouts
	shutdownTimeout = 5 * time.Second
)

func main() {
	// Parse command line flags
	policyDir := flag.String("policy-dir", defaultPolicyDir, "Directory containing policy files")
	logDir := flag.String("log-dir", defaultLogDir, "Directory for log files")
	addr := flag.String("addr", defaultAddr, "Server address")
	logToStdout := flag.Bool("log-stdout", false, "Log to stdout instead of file")
	watchFiles := flag.Bool("watch-files", true, "Enable/disable configuration file watching")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	// Initialize logger
	log.InitLogger(*logToStdout, *debug, *logDir)
	logger := log.GetLogger()

	// Create policy manager
	pm, err := server.NewPolicyManager(*policyDir, logger, *watchFiles)
	if err != nil {
		logger.Fatal("failed to create policy manager", "error", err)
	}
	defer pm.Shutdown()

	// Create HTTP server with timeouts
	mux := http.NewServeMux()
	mux.HandleFunc("/enforce", pm.HandleEnforce)
	mux.HandleFunc("/health", pm.HandleHealth)

	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in a goroutine
	go func() {
		logger.Info("starting server", "addr", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	// Shutdown server
	logger.Info("shutting down server")
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, shutdownTimeout)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown error", "error", err)
	}

	// Shutdown policy manager
	pm.Shutdown()
	logger.Info("server stopped")
}
