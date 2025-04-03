// Copyright 2020 Kentaro Hibino. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

// Package log exports logging related types and functions.
package log

import (
	"fmt"
	"strings"

	"context"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"sync"

	"path/filepath"
)

var (
	logger  *CustomLogger
	slogger *slog.Logger
	logOnce sync.Once
)

// AsynqLoggerAdapter adapts CustomLogger to implement asynq.Logger interface
type AsynqLoggerAdapter struct {
	logger *CustomLogger
}

func (a *AsynqLoggerAdapter) Debug(args ...interface{}) {
	if len(args) > 0 {
		a.logger.Debug(args[0], args[1:]...)
	}
}

func (a *AsynqLoggerAdapter) Info(args ...interface{}) {
	if len(args) > 0 {
		a.logger.Info(args[0], args[1:]...)
	}
}

func (a *AsynqLoggerAdapter) Warn(args ...interface{}) {
	if len(args) > 0 {
		a.logger.Warn(args[0], args[1:]...)
	}
}

func (a *AsynqLoggerAdapter) Error(args ...interface{}) {
	if len(args) > 0 {
		a.logger.Error(args[0], args[1:]...)
	}
}

func (a *AsynqLoggerAdapter) Fatal(args ...interface{}) {
	if len(args) > 0 {
		a.logger.Fatal(args[0], args[1:]...)
	}
}

func trimFilePath(file string, parts int) string {
	// Normalize the path for cross-platform compatibility
	file = filepath.ToSlash(file)

	// Split the path into components
	segments := strings.Split(file, "/")

	// Get the last 'parts' segments
	if len(segments) > parts {
		segments = segments[len(segments)-parts:]
	}

	return strings.Join(segments, "/")
}

type CustomLogger struct {
	base      *slog.Logger
	ownPrefix string
}

func (l *CustomLogger) log(level slog.Level, msg string, args ...any) {
	if level == slog.LevelDebug {
		// Get caller information with a single call to runtime.Caller
		var skip = 2
		_, file, line, ok := runtime.Caller(skip)

		// If not a direct call or from a log file, adjust the skip value
		if ok && (!strings.Contains(file, l.ownPrefix) || strings.Contains(filepath.Base(file), "log")) {
			skip++
			_, file, line, ok = runtime.Caller(skip)
			// Check again for log file
			if ok && strings.Contains(filepath.Base(file), "log") {
				skip++
				_, file, line, ok = runtime.Caller(skip)
			}
		}

		if ok {
			shortFile := trimFilePath(file, 1)
			caller := shortFile + ":" + strconv.Itoa(line)
			args = append(args, slog.Attr{
				Key:   "caller",
				Value: slog.StringValue(caller),
			})
		}
	}

	l.base.Log(context.Background(), level, msg, args...)
}

func (l *CustomLogger) Debug(msg interface{}, args ...interface{}) {
	l.log(slog.LevelDebug, fmt.Sprint(msg), args...)
}

func (l *CustomLogger) Info(msg interface{}, args ...interface{}) {
	l.log(slog.LevelInfo, fmt.Sprint(msg), args...)
}

func (l *CustomLogger) Warn(msg interface{}, args ...interface{}) {
	l.log(slog.LevelWarn, fmt.Sprint(msg), args...)
}

func (l *CustomLogger) Error(msg interface{}, args ...interface{}) {
	l.log(slog.LevelError, fmt.Sprint(msg), args...)
}

func (l *CustomLogger) Fatal(msg interface{}, args ...interface{}) {
	l.log(slog.LevelError, fmt.Sprint(msg), args...)
	os.Exit(1)
}

func (l *CustomLogger) Debugf(format string, args ...interface{}) {
	l.log(slog.LevelDebug, fmt.Sprintf(format, args...))
}

func (l *CustomLogger) Infof(format string, args ...interface{}) {
	l.log(slog.LevelInfo, fmt.Sprintf(format, args...))
}

func (l *CustomLogger) Warnf(format string, args ...interface{}) {
	l.log(slog.LevelWarn, fmt.Sprintf(format, args...))
}

func (l *CustomLogger) Errorf(format string, args ...interface{}) {
	l.log(slog.LevelError, fmt.Sprintf(format, args...))
}

func (l *CustomLogger) Fatalf(format string, args ...interface{}) {
	l.log(slog.LevelError, fmt.Sprintf(format, args...))
	os.Exit(1)
}

// GetLogger returns the singleton instance of CustomLogger
func GetLogger() *CustomLogger {
	logOnce.Do(func() {
		if logger == nil {
			InitLogger(false, false, "audit-logs")
		}
	})
	return logger
}

// InitLogger initializes the logger.
func InitLogger(logToStdout bool, debug bool, logDir string) {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}

	if v, err := strconv.Atoi(os.Getenv("LOG_LEVEL")); err == nil {
		level = slog.Level(v)
	}

	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().Format("2006/01/02 15:04:05 -0700"))
			}
			return a
		},
	}

	var handler slog.Handler
	if logToStdout {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		// Create logs directory if it doesn't exist
		if err := os.MkdirAll(logDir, 0755); err != nil {
			slog.Error("failed to create log directory", "error", err)
			os.Exit(1)
		}

		// Create log file with secure permissions
		logFile, err := os.OpenFile(filepath.Join(logDir, "policy.log"),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			slog.Error("failed to open log file", "error", err)
			os.Exit(1)
		}

		handler = slog.NewJSONHandler(logFile, opts)
	}

	slogger = slog.New(handler)
	logger = NewLogger(slogger)
}

// NewLogger creates and returns a new instance of Logger.
// Log level is set to DebugLevel by default.
func NewLogger(base *slog.Logger) *CustomLogger {
	return &CustomLogger{base: base, ownPrefix: "auto-snapshot"}
}
