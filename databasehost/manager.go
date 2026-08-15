package databasehost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Engine string

const (
	MariaDB    Engine = "mariadb"
	MongoDB    Engine = "mongodb"
	PostgreSQL Engine = "postgresql"
	Redis      Engine = "redis"
)

var (
	ErrUnsupported     = errors.New("unsupported database engine")
	ErrNotInstalled    = errors.New("database engine is not installed")
	ErrDatabaseExists  = errors.New("database already exists")
	ErrDatabaseMissing = errors.New("database does not exist")
	ErrEngineInUse     = errors.New("database engine is still in use")
	ErrInvalidRequest  = errors.New("invalid database request")
	namePattern        = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	userPattern        = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)
)

type specification struct {
	Image        string
	PublicPort   int
	InternalPort int
}

var specifications = map[Engine]specification{
	MariaDB:    {Image: "mariadb:11.8", PublicPort: 3306, InternalPort: 3306},
	MongoDB:    {Image: "mongo:8.0", PublicPort: 27017, InternalPort: 27017},
	PostgreSQL: {Image: "postgres:17", PublicPort: 5432, InternalPort: 5432},
	Redis:      {Image: "redis:8", PublicPort: 6379, InternalPort: 6379},
}

type Database struct {
	Username string `json:"username"`
	Remote   string `json:"remote"`
	Port     int    `json:"port"`
}

type EngineState struct {
	Installed    bool                `json:"installed"`
	Image        string              `json:"image"`
	RootUsername string              `json:"root_username,omitempty"`
	RootPassword string              `json:"root_password"`
	Databases    map[string]Database `json:"databases"`
	LastError    string              `json:"last_error,omitempty"`
}

type state struct {
	Engines map[Engine]*EngineState `json:"engines"`
}

type Status struct {
	Engine    Engine `json:"engine"`
	Installed bool   `json:"installed"`
	Healthy   bool   `json:"healthy"`
	State     string `json:"state"`
	Problem   string `json:"problem,omitempty"`
	Databases int    `json:"databases"`
	Image     string `json:"image"`
	Port      int    `json:"port"`
}

type CreateRequest struct {
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
	Remote   string `json:"remote"`
}

type Connection struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type commandRunner interface {
	Run(context.Context, string, ...string) (string, error)
}

type dockerRunner struct{}

func (dockerRunner) Run(ctx context.Context, stdin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker command failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

type Manager struct {
	mu        sync.Mutex
	statusMu  sync.RWMutex
	root      string
	stateFile string
	state     state
	statuses  map[Engine]Status
	runner    commandRunner
}

var defaultManager *Manager

func Initialize(root string) error {
	m, err := New(root)
	if err != nil {
		return err
	}
	defaultManager = m
	return nil
}

func Default() *Manager {
	if defaultManager == nil {
		panic("databasehost: manager not initialized")
	}
	return defaultManager
}

func New(root string) (*Manager, error) {
	directory := filepath.Join(root, "soar", "databases")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	m := &Manager{
		root:      directory,
		stateFile: filepath.Join(directory, "state.json"),
		state:     state{Engines: map[Engine]*EngineState{}},
		statuses:  map[Engine]Status{},
		runner:    dockerRunner{},
	}
	if b, err := os.ReadFile(m.stateFile); err == nil {
		if err := json.Unmarshal(b, &m.state); err != nil {
			return nil, fmt.Errorf("databasehost: decode state: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if m.state.Engines == nil {
		m.state.Engines = map[Engine]*EngineState{}
	}
	imported := false
	for _, engine := range []Engine{MariaDB, MongoDB, PostgreSQL, Redis} {
		if _, exists := m.state.Engines[engine]; exists {
			continue
		}
		password, databases, found := legacyState(engine)
		if !found || (engine != Redis && password == "") {
			continue
		}
		m.state.Engines[engine] = &EngineState{
			Installed:    true,
			Image:        specifications[engine].Image,
			RootUsername: legacyRootUsername(engine),
			RootPassword: password,
			Databases:    databases,
		}
		imported = true
	}
	if imported {
		if err := m.save(); err != nil {
			return nil, fmt.Errorf("databasehost: import legacy state: %w", err)
		}
	}
	for _, engine := range allEngines() {
		item := m.state.Engines[engine]
		status := baseStatus(engine, item)
		if item == nil {
			status.State = "not_installed"
			status.Problem = "database service is not installed"
		} else {
			status.State = "checking"
			status.Problem = "health check is pending"
		}
		m.statuses[engine] = status
	}
	return m, nil
}

func allEngines() []Engine {
	return []Engine{MariaDB, MongoDB, PostgreSQL, Redis}
}

func baseStatus(engine Engine, item *EngineState) Status {
	spec := specifications[engine]
	status := Status{Engine: engine, Image: spec.Image, Port: spec.PublicPort}
	if item != nil {
		status.Installed = item.Installed
		status.Image = item.Image
		status.Databases = len(item.Databases)
	}
	return status
}

func ParseEngine(value string) (Engine, error) {
	engine := Engine(strings.ToLower(strings.TrimSpace(value)))
	if _, ok := specifications[engine]; !ok {
		return "", ErrUnsupported
	}
	return engine, nil
}

func (m *Manager) save() error {
	b, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	temporary := m.stateFile + ".tmp"
	if err := os.WriteFile(temporary, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, m.stateFile)
}

func randomPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Keep the original container and volume names so nodes can migrate from the
// standalone Stacker provisioner without moving database files.
func containerName(engine Engine) string { return "stacker-database-" + string(engine) }
func volumeName(engine Engine) string    { return containerName(engine) + "-data" }

func legacyRootUsername(engine Engine) string {
	if engine == MongoDB {
		return "stacker"
	}
	return ""
}

func legacyState(engine Engine) (string, map[string]Database, bool) {
	password := ""
	found := false
	if content, err := os.ReadFile(filepath.Join("/etc/stacker-database-agent", string(engine)+".env")); err == nil {
		found = true
		for _, line := range strings.Split(string(content), "\n") {
			if value, found := strings.CutPrefix(line, "ROOT_PASSWORD="); found {
				password = strings.TrimSpace(value)
				break
			}
		}
	}
	databases := map[string]Database{}
	if content, err := os.ReadFile(filepath.Join("/var/lib/stacker-database-agent", string(engine)+".json")); err == nil {
		found = true
		var value struct {
			Databases map[string]Database `json:"databases"`
		}
		if json.Unmarshal(content, &value) == nil && value.Databases != nil {
			databases = value.Databases
		}
	}
	return password, databases, found
}

func (m *Manager) run(ctx context.Context, stdin string, args ...string) (string, error) {
	return m.runner.Run(ctx, stdin, args...)
}

func (m *Manager) containerExists(ctx context.Context, name string) bool {
	_, err := m.run(ctx, "", "inspect", name)
	return err == nil
}

func (m *Manager) containerRunning(ctx context.Context, name string) bool {
	out, err := m.run(ctx, "", "inspect", "-f", "{{.State.Running}}", name)
	return err == nil && out == "true"
}

func (m *Manager) containerProblem(ctx context.Context, name string) string {
	out, err := m.run(ctx, "", "inspect", "-f", "{{.State.Status}}{{if .State.Error}}: {{.State.Error}}{{end}}", name)
	if err != nil {
		return "container is missing"
	}
	if strings.TrimSpace(out) == "" {
		return "container state is unavailable"
	}
	return out
}

func (m *Manager) createEngineContainer(ctx context.Context, engine Engine, item *EngineState) error {
	spec := specifications[engine]
	args := []string{"run", "-d", "--name", containerName(engine), "--restart", "unless-stopped", "-p", fmt.Sprintf("%d:%d", spec.PublicPort, spec.InternalPort)}
	switch engine {
	case MariaDB:
		args = append(args, "-e", "MARIADB_ROOT_PASSWORD="+item.RootPassword, "-v", volumeName(engine)+":/var/lib/mysql", item.Image)
	case MongoDB:
		args = append(args, "-e", "MONGO_INITDB_ROOT_USERNAME="+item.RootUsername, "-e", "MONGO_INITDB_ROOT_PASSWORD="+item.RootPassword, "-v", volumeName(engine)+":/data/db", item.Image)
	case PostgreSQL:
		args = append(args, "-e", "POSTGRES_PASSWORD="+item.RootPassword, "-v", volumeName(engine)+":/var/lib/postgresql/data", item.Image)
	default:
		return ErrUnsupported
	}
	_, err := m.run(ctx, "", args...)
	return err
}

func (m *Manager) health(ctx context.Context, engine Engine, item *EngineState) error {
	if engine == Redis {
		if _, err := m.run(ctx, "", "info"); err != nil {
			return fmt.Errorf("Docker is unavailable: %w", err)
		}
		for database := range item.Databases {
			name := "stacker-redis-" + database
			if !m.containerRunning(ctx, name) {
				return fmt.Errorf("Redis container for database %s is not running (%s)", database, m.containerProblem(ctx, name))
			}
		}
		return nil
	}
	if !m.containerRunning(ctx, containerName(engine)) {
		return fmt.Errorf("%s container is not running (%s)", engine, m.containerProblem(ctx, containerName(engine)))
	}
	var args []string
	switch engine {
	case MariaDB:
		args = []string{"exec", containerName(engine), "mariadb-admin", "ping", "-uroot", "-p" + item.RootPassword, "--silent"}
	case MongoDB:
		args = []string{"exec", containerName(engine), "mongosh", "--quiet", "--username", item.RootUsername, "--password", item.RootPassword, "--authenticationDatabase", "admin", "--eval", "quit(db.adminCommand({ping:1}).ok ? 0 : 1)"}
	case PostgreSQL:
		args = []string{"exec", containerName(engine), "pg_isready", "-U", "postgres"}
	default:
		return ErrUnsupported
	}
	_, err := m.run(ctx, "", args...)
	if err != nil {
		return fmt.Errorf("%s health check failed: %w", engine, err)
	}
	return nil
}

func safeProblem(item *EngineState, err error) string {
	if err == nil {
		return ""
	}
	problem := err.Error()
	if item != nil && item.RootPassword != "" {
		problem = strings.ReplaceAll(problem, item.RootPassword, "[redacted]")
	}
	if len(problem) > 500 {
		problem = problem[:500]
	}
	return problem
}

func (m *Manager) statusLocked(ctx context.Context, engine Engine) Status {
	item, exists := m.state.Engines[engine]
	status := baseStatus(engine, item)
	if !exists {
		status.State = "not_installed"
		status.Problem = "database service is not installed"
		return status
	}
	if !item.Installed {
		status.State = "failed"
		status.Problem = item.LastError
		if status.Problem == "" {
			status.Problem = "database service installation has not completed"
		}
		return status
	}
	if err := m.health(ctx, engine, item); err != nil {
		status.State = "offline"
		status.Problem = safeProblem(item, err)
		return status
	}
	status.Healthy = true
	status.State = "online"
	return status
}

func (m *Manager) setStatus(status Status) {
	m.statusMu.Lock()
	m.statuses[status.Engine] = status
	m.statusMu.Unlock()
}

func (m *Manager) List(_ context.Context) []Status {
	m.statusMu.RLock()
	defer m.statusMu.RUnlock()
	statuses := make([]Status, 0, len(specifications))
	for _, engine := range allEngines() {
		statuses = append(statuses, m.statuses[engine])
	}
	return statuses
}

func (m *Manager) Status(_ context.Context, engine Engine) Status {
	m.statusMu.RLock()
	defer m.statusMu.RUnlock()
	return m.statuses[engine]
}

func (m *Manager) Install(ctx context.Context, engine Engine, update bool) (result Status, returnErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	spec, ok := specifications[engine]
	if !ok {
		return Status{}, ErrUnsupported
	}
	item := m.state.Engines[engine]
	installing := baseStatus(engine, item)
	installing.State = "installing"
	installing.Problem = "installing database service"
	m.setStatus(installing)
	defer func() {
		if returnErr != nil {
			problem := safeProblem(item, returnErr)
			if item != nil {
				item.LastError = problem
				_ = m.save()
			}
			status := baseStatus(engine, item)
			status.Healthy = false
			status.State = "failed"
			status.Problem = problem
			m.setStatus(status)
			result = status
			return
		}
		if item != nil {
			item.LastError = ""
		}
		status := m.statusLocked(ctx, engine)
		m.setStatus(status)
		result = status
	}()
	if item == nil {
		password, databases, _ := legacyState(engine)
		if password == "" {
			var err error
			password, err = randomPassword()
			if err != nil {
				return Status{}, err
			}
		}
		rootUsername := ""
		if engine == MongoDB {
			rootUsername = "soar"
		}
		item = &EngineState{Image: spec.Image, RootUsername: rootUsername, RootPassword: password, Databases: databases}
		m.state.Engines[engine] = item
		if err := m.save(); err != nil {
			delete(m.state.Engines, engine)
			return Status{}, err
		}
	}
	if _, err := m.run(ctx, "", "pull", spec.Image); err != nil {
		return Status{}, err
	}
	item.Image = spec.Image
	if engine != Redis {
		name := containerName(engine)
		exists := m.containerExists(ctx, name)
		if update && exists {
			if _, err := m.run(ctx, "", "rm", "-f", name); err != nil {
				return Status{}, err
			}
			exists = false
		}
		if !exists {
			if err := m.createEngineContainer(ctx, engine, item); err != nil {
				return Status{}, err
			}
		} else if !m.containerRunning(ctx, name) {
			if _, err := m.run(ctx, "", "start", name); err != nil {
				return Status{}, err
			}
		}
	} else if update {
		for database, entry := range item.Databases {
			name := "stacker-redis-" + database
			_, _ = m.run(ctx, "", "rm", "-f", name)
			if err := m.runRedisContainer(ctx, database, entry.Port, m.redisConfigPath(database), item.Image); err != nil {
				return Status{}, err
			}
		}
	}
	if err := m.save(); err != nil {
		return Status{}, err
	}
	for attempt := 0; attempt < 45; attempt++ {
		if m.health(ctx, engine, item) == nil {
			item.Installed = true
			item.LastError = ""
			if err := m.save(); err != nil {
				return Status{}, err
			}
			return m.statusLocked(ctx, engine), nil
		}
		select {
		case <-ctx.Done():
			return Status{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return m.statusLocked(ctx, engine), errors.New("database engine did not become healthy")
}

// Refresh performs live health checks without making the API wait for an
// installation or image pull. API handlers always serve the latest snapshot.
func (m *Manager) Refresh(ctx context.Context) []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	statuses := make([]Status, 0, len(specifications))
	for _, engine := range allEngines() {
		status := m.statusLocked(ctx, engine)
		m.setStatus(status)
		statuses = append(statuses, status)
	}
	return statuses
}

func (m *Manager) reconcile(ctx context.Context) {
	for _, status := range m.Refresh(ctx) {
		desiredImage := specifications[status.Engine].Image
		if status.Healthy && status.Image == desiredImage {
			continue
		}
		installCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		_, _ = m.Install(installCtx, status.Engine, status.Installed && status.Image != desiredImage)
		cancel()
		if ctx.Err() != nil {
			return
		}
	}
}

// Run continuously installs all bundled engines, refreshes their health, and
// repairs stopped services. It is intentionally asynchronous so container API
// traffic remains available while large database images are being pulled.
func (m *Manager) Run(ctx context.Context) {
	m.reconcile(ctx)
	healthTicker := time.NewTicker(30 * time.Second)
	reconcileTicker := time.NewTicker(5 * time.Minute)
	defer healthTicker.Stop()
	defer reconcileTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-healthTicker.C:
			m.Refresh(ctx)
		case <-reconcileTicker.C:
			m.reconcile(ctx)
		}
	}
}

func sqlString(value string) string       { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
func mysqlIdentifier(value string) string { return "`" + strings.ReplaceAll(value, "`", "``") + "`" }
func pgIdentifier(value string) string    { return `"` + strings.ReplaceAll(value, `"`, `""`) + `"` }

func validateRequest(request CreateRequest) error {
	if !namePattern.MatchString(request.Database) || !userPattern.MatchString(request.Username) || len(request.Password) < 16 || len(request.Password) > 256 {
		return ErrInvalidRequest
	}
	return nil
}

func (m *Manager) executeMariaDB(ctx context.Context, password, sql string) error {
	_, err := m.run(ctx, sql, "exec", "-i", containerName(MariaDB), "mariadb", "-uroot", "-p"+password)
	return err
}

func (m *Manager) executePostgreSQL(ctx context.Context, sql string) error {
	_, err := m.run(ctx, sql, "exec", "-i", containerName(PostgreSQL), "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres")
	return err
}

func (m *Manager) executeMongoDB(ctx context.Context, username, password, script string) error {
	_, err := m.run(ctx, "", "exec", containerName(MongoDB), "mongosh", "--quiet", "--username", username, "--password", password, "--authenticationDatabase", "admin", "--eval", script)
	return err
}

func (m *Manager) nextRedisPort(item *EngineState) (int, error) {
	used := map[int]bool{}
	for _, database := range item.Databases {
		used[database.Port] = true
	}
	for port := 16379; port < 17379; port++ {
		if !used[port] {
			return port, nil
		}
	}
	return 0, errors.New("no Redis database ports available")
}

func (m *Manager) redisConfig(request CreateRequest) (string, error) {
	directory := filepath.Join(m.root, "redis", request.Database)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(request.Password))
	content := "appendonly yes\nprotected-mode yes\nuser default off\n" +
		fmt.Sprintf("user %s on #%x ~* +@all\n", request.Username, hash)
	path := filepath.Join(directory, "redis.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (m *Manager) redisConfigPath(database string) string {
	current := filepath.Join(m.root, "redis", database, "redis.conf")
	if _, err := os.Stat(current); err == nil {
		return current
	}
	return filepath.Join("/var/lib/stacker-database-agent/redis", database, "redis.conf")
}

func (m *Manager) runRedisContainer(ctx context.Context, database string, port int, configPath, image string) error {
	name := "stacker-redis-" + database
	args := []string{"run", "-d", "--name", name, "--restart", "unless-stopped", "-p", fmt.Sprintf("%d:6379", port), "-v", name + "-data:/data", "-v", configPath + ":/usr/local/etc/redis/redis.conf:ro", image, "redis-server", "/usr/local/etc/redis/redis.conf"}
	_, err := m.run(ctx, "", args...)
	return err
}

func (m *Manager) Create(ctx context.Context, host string, engine Engine, request CreateRequest) (Connection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validateRequest(request); err != nil {
		return Connection{}, err
	}
	item := m.state.Engines[engine]
	if item == nil || !item.Installed {
		return Connection{}, ErrNotInstalled
	}
	if _, exists := item.Databases[request.Database]; exists {
		return Connection{}, ErrDatabaseExists
	}
	remote := request.Remote
	if remote == "" {
		remote = "%"
	}
	port := specifications[engine].PublicPort
	switch engine {
	case MariaDB:
		user := sqlString(request.Username) + "@" + sqlString(remote)
		sql := fmt.Sprintf("CREATE DATABASE %s;\nCREATE USER %s IDENTIFIED BY %s;\nGRANT ALL PRIVILEGES ON %s.* TO %s;\nFLUSH PRIVILEGES;\n", mysqlIdentifier(request.Database), user, sqlString(request.Password), mysqlIdentifier(request.Database), user)
		if err := m.executeMariaDB(ctx, item.RootPassword, sql); err != nil {
			return Connection{}, err
		}
	case PostgreSQL:
		sql := fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD %s;\nCREATE DATABASE %s OWNER %s;\nREVOKE CONNECT ON DATABASE %s FROM PUBLIC;\nGRANT CONNECT ON DATABASE %s TO %s;\n", pgIdentifier(request.Username), sqlString(request.Password), pgIdentifier(request.Database), pgIdentifier(request.Username), pgIdentifier(request.Database), pgIdentifier(request.Database), pgIdentifier(request.Username))
		if err := m.executePostgreSQL(ctx, sql); err != nil {
			return Connection{}, err
		}
	case MongoDB:
		script := fmt.Sprintf("const n=%s;const u=%s;const p=%s;db.getSiblingDB(n).createUser({user:u,pwd:p,roles:[{role:'readWrite',db:n}]});", jsonString(request.Database), jsonString(request.Username), jsonString(request.Password))
		if err := m.executeMongoDB(ctx, item.RootUsername, item.RootPassword, script); err != nil {
			return Connection{}, err
		}
	case Redis:
		var err error
		port, err = m.nextRedisPort(item)
		if err != nil {
			return Connection{}, err
		}
		configPath, err := m.redisConfig(request)
		if err != nil {
			return Connection{}, err
		}
		if err := m.runRedisContainer(ctx, request.Database, port, configPath, item.Image); err != nil {
			return Connection{}, err
		}
	default:
		return Connection{}, ErrUnsupported
	}
	item.Databases[request.Database] = Database{Username: request.Username, Remote: remote, Port: port}
	if err := m.save(); err != nil {
		return Connection{}, err
	}
	return Connection{Host: host, Port: port}, nil
}

func jsonString(value string) string {
	b, _ := json.Marshal(value)
	return string(b)
}

func (m *Manager) Delete(ctx context.Context, engine Engine, database string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	item := m.state.Engines[engine]
	if item == nil || !item.Installed {
		return ErrNotInstalled
	}
	entry, ok := item.Databases[database]
	if !ok {
		return ErrDatabaseMissing
	}
	switch engine {
	case MariaDB:
		user := sqlString(entry.Username) + "@" + sqlString(entry.Remote)
		if err := m.executeMariaDB(ctx, item.RootPassword, fmt.Sprintf("DROP DATABASE IF EXISTS %s;\nDROP USER IF EXISTS %s;\n", mysqlIdentifier(database), user)); err != nil {
			return err
		}
	case PostgreSQL:
		sql := fmt.Sprintf("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s AND pid <> pg_backend_pid();\nDROP DATABASE IF EXISTS %s;\nDROP ROLE IF EXISTS %s;\n", sqlString(database), pgIdentifier(database), pgIdentifier(entry.Username))
		if err := m.executePostgreSQL(ctx, sql); err != nil {
			return err
		}
	case MongoDB:
		if err := m.executeMongoDB(ctx, item.RootUsername, item.RootPassword, "db.getSiblingDB("+jsonString(database)+").dropDatabase();"); err != nil {
			return err
		}
	case Redis:
		name := "stacker-redis-" + database
		_, _ = m.run(ctx, "", "rm", "-f", name)
		_, _ = m.run(ctx, "", "volume", "rm", name+"-data")
		_ = os.RemoveAll(filepath.Join(m.root, "redis", database))
	default:
		return ErrUnsupported
	}
	delete(item.Databases, database)
	return m.save()
}

func (m *Manager) RotatePassword(ctx context.Context, engine Engine, database, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(password) < 16 || len(password) > 256 {
		return ErrInvalidRequest
	}
	item := m.state.Engines[engine]
	if item == nil || !item.Installed {
		return ErrNotInstalled
	}
	entry, ok := item.Databases[database]
	if !ok {
		return ErrDatabaseMissing
	}
	switch engine {
	case MariaDB:
		user := sqlString(entry.Username) + "@" + sqlString(entry.Remote)
		return m.executeMariaDB(ctx, item.RootPassword, fmt.Sprintf("ALTER USER %s IDENTIFIED BY %s;\n", user, sqlString(password)))
	case PostgreSQL:
		return m.executePostgreSQL(ctx, fmt.Sprintf("ALTER ROLE %s PASSWORD %s;\n", pgIdentifier(entry.Username), sqlString(password)))
	case MongoDB:
		return m.executeMongoDB(ctx, item.RootUsername, item.RootPassword, "db.getSiblingDB("+jsonString(database)+").updateUser("+jsonString(entry.Username)+",{pwd:"+jsonString(password)+"});")
	case Redis:
		request := CreateRequest{Database: database, Username: entry.Username, Password: password, Remote: entry.Remote}
		if _, err := m.redisConfig(request); err != nil {
			return err
		}
		_, err := m.run(ctx, "", "restart", "stacker-redis-"+database)
		return err
	default:
		return ErrUnsupported
	}
}

func (m *Manager) Uninstall(ctx context.Context, engine Engine) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	item := m.state.Engines[engine]
	if item == nil {
		return ErrNotInstalled
	}
	if len(item.Databases) > 0 {
		return ErrEngineInUse
	}
	if engine != Redis {
		_, _ = m.run(ctx, "", "rm", "-f", containerName(engine))
		_, _ = m.run(ctx, "", "volume", "rm", volumeName(engine))
	}
	delete(m.state.Engines, engine)
	if err := m.save(); err != nil {
		return err
	}
	status := baseStatus(engine, nil)
	status.State = "not_installed"
	status.Problem = "database service is not installed"
	m.setStatus(status)
	return nil
}

func PublicPort(engine Engine) int { return specifications[engine].PublicPort }

func ParsePort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("invalid port")
	}
	return port, nil
}
