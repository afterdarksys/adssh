package security

func (e *Engine) SetLastDenial(sessionID string, explanation CommandExplanation) {
	e.denialMu.Lock()
	defer e.denialMu.Unlock()
	e.lastDenials[sessionID] = explanation
}

func (e *Engine) LastDenial(sessionID string) (CommandExplanation, bool) {
	e.denialMu.RLock()
	defer e.denialMu.RUnlock()
	explanation, ok := e.lastDenials[sessionID]
	return explanation, ok
}

func (e *Engine) ClearLastDenial(sessionID string) {
	e.denialMu.Lock()
	defer e.denialMu.Unlock()
	delete(e.lastDenials, sessionID)
}

func (e *Engine) rememberDeniedCommand(sessionID string, args []string) {
	explanation, err := e.ExplainCommand(sessionID, args)
	if err != nil {
		return
	}
	if explanation.Outcome != "allowed" {
		e.SetLastDenial(sessionID, explanation)
	}
}
