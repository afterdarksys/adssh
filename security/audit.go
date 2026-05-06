package security

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var auditLogger *log.Logger

func init() {
	homeDir, _ := os.UserHomeDir()
	logFile, err := os.OpenFile(filepath.Join(homeDir, ".adssh_audit.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize audit logger: %v\n", err)
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
