package databasehost

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeRunner struct {
	created bool
	stdin   []string
}

func (f *fakeRunner) Run(_ context.Context, stdin string, args ...string) (string, error) {
	if stdin != "" {
		f.stdin = append(f.stdin, stdin)
	}
	if len(args) >= 2 && args[0] == "inspect" && args[1] != "-f" {
		if !f.created {
			return "", errors.New("missing")
		}
		return "container", nil
	}
	if len(args) > 0 && args[0] == "run" {
		f.created = true
	}
	if len(args) >= 3 && args[0] == "inspect" && args[1] == "-f" {
		return "true", nil
	}
	return "", nil
}

func TestParseEngine(t *testing.T) {
	engine, err := ParseEngine("PostgreSQL")
	if err != nil || engine != PostgreSQL {
		t.Fatalf("expected postgresql, got %q (%v)", engine, err)
	}
	if _, err := ParseEngine("mysql"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected unsupported engine, got %v", err)
	}
}

func TestMariaDBCreatesScopedUser(t *testing.T) {
	m, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	m.runner = runner
	if _, err := m.Install(context.Background(), MariaDB, false); err != nil {
		t.Fatal(err)
	}
	request := CreateRequest{Database: "s_1_main", Username: "u_1_main", Password: strings.Repeat("p", 24), Remote: "%"}
	if _, err := m.Create(context.Background(), "node.example.com", MariaDB, request); err != nil {
		t.Fatal(err)
	}
	if len(runner.stdin) == 0 {
		t.Fatal("expected SQL input")
	}
	sql := runner.stdin[len(runner.stdin)-1]
	if !strings.Contains(sql, "GRANT ALL PRIVILEGES ON `s_1_main`.* TO 'u_1_main'@'%'") {
		t.Fatalf("database user was not scoped to its database: %s", sql)
	}
}

func TestUninstallBlockedWhileDatabaseExists(t *testing.T) {
	m, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m.state.Engines[Redis] = &EngineState{Installed: true, Image: specifications[Redis].Image, Databases: map[string]Database{"cache": {Username: "cache", Port: 16379}}}
	if err := m.Uninstall(context.Background(), Redis); !errors.Is(err, ErrEngineInUse) {
		t.Fatalf("expected in-use error, got %v", err)
	}
}

func TestReconcileInstallsEveryBundledEngine(t *testing.T) {
	m, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m.runner = &fakeRunner{}
	m.reconcile(context.Background())
	for _, status := range m.List(context.Background()) {
		if !status.Installed || !status.Healthy || status.State != "online" {
			t.Fatalf("expected %s to be online after reconciliation: %+v", status.Engine, status)
		}
		if status.Problem != "" {
			t.Fatalf("expected %s to have no problem, got %q", status.Engine, status.Problem)
		}
	}
}
