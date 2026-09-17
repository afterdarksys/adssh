package agent

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Task is a single named, pre-approved instrumentation task. The network names
// ONLY the task; the virtual binary and its arguments are supplied here from the
// operator-controlled allowlist file and are never taken from the request.
type Task struct {
	// VBin is the name of the adssh virtual binary to dispatch (e.g. "proc").
	VBin string `yaml:"vbin"`
	// Args are the FIXED arguments passed to the virtual binary, in addition to
	// the binary name itself. They come from the file, never from the client.
	Args []string `yaml:"args"`
	// Description is a short human-readable summary surfaced by GET /v1/tasks.
	Description string `yaml:"description"`
	// Risk is an advisory label (e.g. "low") threaded into the AgentClaim so the
	// Rego policy may reason about it.
	Risk string `yaml:"risk"`
}

// TaskSet is an immutable, name-keyed allowlist of instrumentation tasks.
type TaskSet struct {
	tasks map[string]Task
}

// tasksDocument is the on-disk YAML grammar:
//
//	tasks:
//	  <task-name>:
//	    vbin: <virtual-binary-name>
//	    args: [<fixed>, <args>, ...]
//	    description: <text>
//	    risk: <label>
type tasksDocument struct {
	Tasks map[string]Task `yaml:"tasks"`
}

// LoadTasks reads and parses the allowlist file at path. A missing file yields
// an empty (deny-everything) allowlist rather than an error, so a host with no
// tasks configured refuses every task while still serving health and an empty
// task list. A malformed file IS an error (fail closed — do not silently run
// with a half-parsed allowlist).
func LoadTasks(path string) (*TaskSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &TaskSet{tasks: map[string]Task{}}, nil
		}
		return nil, fmt.Errorf("agent: read tasks file %q: %w", path, err)
	}
	ts, err := ParseTasks(data)
	if err != nil {
		return nil, fmt.Errorf("agent: %q: %w", path, err)
	}
	return ts, nil
}

// ParseTasks parses an allowlist document from raw YAML bytes.
func ParseTasks(data []byte) (*TaskSet, error) {
	var doc tasksDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse tasks file: %w", err)
	}
	ts := &TaskSet{tasks: make(map[string]Task, len(doc.Tasks))}
	for name, t := range doc.Tasks {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("task name cannot be empty")
		}
		if strings.TrimSpace(t.VBin) == "" {
			return nil, fmt.Errorf("task %q: vbin is required", name)
		}
		ts.tasks[name] = t
	}
	return ts, nil
}

// Get returns the task registered under name.
func (ts *TaskSet) Get(name string) (Task, bool) {
	t, ok := ts.tasks[name]
	return t, ok
}

// Len reports how many tasks are in the allowlist.
func (ts *TaskSet) Len() int { return len(ts.tasks) }

// Names returns the allowlisted task names, sorted.
func (ts *TaskSet) Names() []string {
	out := make([]string, 0, len(ts.tasks))
	for name := range ts.tasks {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
