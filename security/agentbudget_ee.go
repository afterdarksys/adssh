//go:build ee

// Threats: a managed agent must not keep spending after its sponsor ends,
// its command count is exhausted, its byte budget is exhausted, or its
// deadline passes. An unbound session is not charged. Clearing the budget
// removes the charge. The stored allow list is this charge map. The fixed
// agent allowlist is a separate gate that already ran.
// Non-goals: a budget does not authorize a command by itself and does not
// change the OS uid. An empty sponsor is not a human sponsor.

package security

import (
	"errors"
	"sync"
	"time"

	"github.com/afterdarksys/adssh/internal/sys"
)

// AgentBudget is the spend limit bound to one managed-agent session.
// A zero Deadline means no deadline. Bytes 0 fails closed.
type AgentBudget struct {
	Allow    []string
	Cmds     int
	Bytes    int64
	Deadline time.Time
	Sponsor  string
}

type agentCharge struct {
	allow     map[string]struct{}
	cmdsLeft  int
	bytesLeft int64
	deadline  time.Time
	sponsor   string
}

var (
	agentBudgetMu sync.Mutex
	agentBudgets  = map[string]*agentCharge{}
)

// BindAgentBudget replaces any charge already stored for sessionID.
// An empty session id fails closed.
func BindAgentBudget(sessionID string, b AgentBudget) error {
	if sessionID == "" {
		return errors.New("admin plane: agent budget")
	}
	allow := make(map[string]struct{}, len(b.Allow))
	for _, name := range b.Allow {
		allow[name] = struct{}{}
	}
	agentBudgetMu.Lock()
	defer agentBudgetMu.Unlock()
	agentBudgets[sessionID] = &agentCharge{
		allow:     allow,
		cmdsLeft:  b.Cmds,
		bytesLeft: b.Bytes,
		deadline:  b.Deadline,
		sponsor:   b.Sponsor,
	}
	return nil
}

// ClearAgentBudget removes the charge for sessionID. A missing entry is a no-op.
func ClearAgentBudget(sessionID string) {
	agentBudgetMu.Lock()
	delete(agentBudgets, sessionID)
	agentBudgetMu.Unlock()
}

// chargeAgentCommand spends one command and one token byte.
// An unbound session is a no-op. A dead sponsor is reported before exhaustion.
func chargeAgentCommand(sessionID, name string) error {
	agentBudgetMu.Lock()
	defer agentBudgetMu.Unlock()
	ch, ok := agentBudgets[sessionID]
	if !ok {
		return nil
	}
	if ch.sponsor == "" {
		return errors.New("admin plane: agent sponsor ended")
	}
	sess := sys.GetSession(ch.sponsor)
	if sess == nil || sess.Info().Terminated {
		return errors.New("admin plane: agent sponsor ended")
	}
	if _, allowed := ch.allow[name]; !allowed {
		return errors.New("admin plane: agent budget")
	}
	if !ch.deadline.IsZero() && !time.Now().Before(ch.deadline) {
		return errors.New("admin plane: agent budget")
	}
	if ch.cmdsLeft <= 0 || ch.bytesLeft <= 0 {
		return errors.New("admin plane: agent budget")
	}
	ch.cmdsLeft--
	ch.bytesLeft--
	return nil
}
