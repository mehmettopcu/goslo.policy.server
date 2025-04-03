package log

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLogger(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "log-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test stdout logging
	InitLogger(true, true, tempDir)
	logger := GetLogger()
	logger.Info("test stdout message")

	// Test file logging
	InitLogger(false, true, tempDir)
	logger = GetLogger()
	logger.Info("test file message")

	// Test log file creation
	logFile := filepath.Join(tempDir, "policy.log")
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Errorf("Log file was not created: %v", err)
	}

	// Test log file permissions
	info, err := os.Stat(logFile)
	if err != nil {
		t.Errorf("Failed to stat log file: %v", err)
	}
	if info.Mode() != 0600 {
		t.Errorf("Expected log file permissions 0600, got %v", info.Mode())
	}

	// Test logging methods
	logger.Info("test info message")
	logger.Error("test error message")
	logger.Debug("test debug message")
	logger.Warn("test warning message")

	// Test formatted logging
	logger.Infof("test info message with %s", "format")
	logger.Errorf("test error message with %s", "format")
	logger.Debugf("test debug message with %s", "format")
	logger.Warnf("test warning message with %s", "format")
}

func TestLoggerConcurrency(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "log-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize logger
	InitLogger(false, true, tempDir)
	logger := GetLogger()

	// Run concurrent logging
	const numGoroutines = 100
	done := make(chan bool)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			logger.Infof("goroutine %d: test message", id)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestLoggerErrorHandling(t *testing.T) {
	// Test with invalid log directory
	InitLogger(false, true, "/tmp/nonexistent/directory")
	logger := GetLogger()

	// These should not panic
	logger.Info("test message")
	logger.Error("test error")
	logger.Debug("test debug")
	logger.Warn("test warning")
}
