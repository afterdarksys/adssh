package security

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var auditLogger *log.Logger

// InitAuditLog initialises the audit logger at the given path.
// The directory is created if it does not exist.
// Called once at startup with the path from AppConfig.
func InitAuditLog(path string) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create audit log directory: %v\n", err)
		return
	}
	logFile, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize audit logger at %s: %v\n", path, err)
		return
	}
	auditLogger = log.New(logFile, "AUDIT: ", log.Ldate|log.Ltime)
}

func LogCommand(source string, cmd string) {
	if auditLogger != nil {
		auditLogger.Printf("[%s] %s\n", source, cmd)
	}
}

func LogEvent(event string) {
	if auditLogger != nil {
		auditLogger.Println(event)
	}
}
