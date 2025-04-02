package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/mehmettopcu/goslo.policy.server/policy"
	"gopkg.in/yaml.v3"
)

// PolicyConfig represents the policy configuration for a service
type PolicyConfig struct {
	Rules map[string]string `yaml:",inline"`
}

// PolicyManager handles policy file management and caching with minimal locking
type PolicyManager struct {
	policyDir  string
	enforcers  map[string]*policy.Enforcer
	mu         sync.RWMutex
	fileCache  map[string]time.Time
	logger     *slog.Logger
	reloadChan chan struct{}
	wg         sync.WaitGroup
}

// NewPolicyManager creates a new policy manager instance
func NewPolicyManager(dir, logDir string) (*PolicyManager, error) {
	// Create logs directory if it doesn't exist
	if logDir == "" {
		logDir = "logs"
	}
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	// Create log file
	logFile, err := os.OpenFile(filepath.Join(logDir, "policy.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	// Create JSON logger
	logger := slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	pm := &PolicyManager{
		policyDir:  dir,
		enforcers:  make(map[string]*policy.Enforcer),
		fileCache:  make(map[string]time.Time),
		logger:     logger,
		reloadChan: make(chan struct{}, 1),
	}

	// Load initial policies
	if err := pm.loadAllPolicies(); err != nil {
		return nil, err
	}

	// Start watching for policy changes
	pm.wg.Add(1)
	go pm.watchPolicyDir()

	return pm, nil
}

// loadAllPolicies loads all policy files from the directory
func (pm *PolicyManager) loadAllPolicies() error {
	tmpEnforcers := make(map[string]*policy.Enforcer)
	tmpFileCache := make(map[string]time.Time)

	err := filepath.Walk(pm.policyDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		service := filepath.Base(path[:len(path)-len(ext)])
		if err := pm.loadSinglePolicy(path, service, info.ModTime(), tmpEnforcers, tmpFileCache); err != nil {
			pm.logger.Error("failed to load policy file",
				"path", path,
				"error", err,
			)
			return nil
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk policy directory: %v", err)
	}

	// Update cache atomically
	pm.mu.Lock()
	pm.enforcers = tmpEnforcers
	pm.fileCache = tmpFileCache
	pm.mu.Unlock()

	return nil
}

// loadSinglePolicy loads a single policy file
func (pm *PolicyManager) loadSinglePolicy(path, service string, modTime time.Time, tmpEnforcers map[string]*policy.Enforcer, tmpFileCache map[string]time.Time) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	var config PolicyConfig
	if err := yaml.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("failed to parse YAML: %v", err)
	}

	enforcer, err := policy.NewEnforcer(config.Rules)
	if err != nil {
		return fmt.Errorf("failed to create enforcer: %v", err)
	}

	tmpEnforcers[service] = enforcer
	tmpFileCache[path] = modTime

	return nil
}

// watchPolicyDir monitors policy files for changes
func (pm *PolicyManager) watchPolicyDir() {
	defer pm.wg.Done()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		pm.logger.Error("failed to create watcher", "error", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(pm.policyDir); err != nil {
		pm.logger.Error("failed to add policy directory to watcher", "error", err)
		return
	}

	for {
		select {
		case <-pm.reloadChan:
			return
		case event := <-watcher.Events:
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove) != 0 {
				pm.handleFileChange(event.Name)
			}
		case err := <-watcher.Errors:
			pm.logger.Error("watcher error", "error", err)
		}
	}
}

// handleFileChange handles file change events
func (pm *PolicyManager) handleFileChange(path string) {
	ext := filepath.Ext(path)
	if ext != ".yaml" && ext != ".yml" {
		return
	}

	service := filepath.Base(path[:len(path)-len(ext)])

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		pm.removeFromCache(service, path)
		return
	}

	if err != nil || info.IsDir() {
		return
	}

	// Check file modification time
	pm.mu.RLock()
	lastMod, exists := pm.fileCache[path]
	pm.mu.RUnlock()

	if exists && info.ModTime().Equal(lastMod) {
		return
	}

	// Load the updated policy
	if err := pm.loadSinglePolicy(path, service, info.ModTime(), pm.enforcers, pm.fileCache); err != nil {
		pm.logger.Error("failed to reload policy file",
			"path", path,
			"error", err,
		)
		return
	}

	pm.logger.Info("reloaded policy file", "path", path)
}

// removeFromCache removes a policy from the cache
func (pm *PolicyManager) removeFromCache(service, path string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	delete(pm.enforcers, service)
	delete(pm.fileCache, path)

	pm.logger.Info("removed policy from cache", "service", service)
}

// GetPolicy retrieves a policy enforcer for a service
func (pm *PolicyManager) GetPolicy(service string) (*policy.Enforcer, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	enforcer, ok := pm.enforcers[service]
	return enforcer, ok
}

// Shutdown gracefully stops the policy manager
func (pm *PolicyManager) Shutdown() {
	select {
	case <-pm.reloadChan:
		// Channel already closed
	default:
		close(pm.reloadChan)
	}
	pm.wg.Wait()
}

// StartServerWithContext starts the policy server with context support for graceful shutdown
func (pm *PolicyManager) StartServerWithContext(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/enforce", pm.HandleEnforce)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			pm.logger.Error("failed to write health response", "error", err)
		}
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Start server in a goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			pm.logger.Error("server error", "error", err)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown failed: %v", err)
	}

	return nil
}

// HandleEnforce handles policy enforcement requests with optimized locking
func (pm *PolicyManager) HandleEnforce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		if err := json.NewEncoder(w).Encode(EnforceResponse{
			Allowed: false,
			Error:   "Method not allowed",
		}); err != nil {
			pm.logger.Error("failed to encode response", "error", err)
			return
		}
		return
	}

	var req EnforceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(EnforceResponse{
			Allowed: false,
			Error:   "Invalid request body",
		}); err != nil {
			pm.logger.Error("failed to encode response", "error", err)
			return
		}
		return
	}

	// Get enforcer with minimal locking
	enforcer, exists := pm.GetPolicy(req.Service)
	if !exists {
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(EnforceResponse{
			Allowed: false,
			Error:   fmt.Sprintf("Service %s not found", req.Service),
		}); err != nil {
			pm.logger.Error("failed to encode response", "error", err)
			return
		}
		return
	}

	// Create policy context with all available fields
	ctx := policy.Context{
		Auth: map[string]string{
			"user_id":             req.Auth.UserID,
			"domain_id":           req.Auth.DomainID,
			"project_id":          req.Auth.ProjectID,
			"user_domain_id":      req.Auth.UserDomainID,
			"project_domain_id":   req.Auth.ProjectDomainID,
			"username":            req.Auth.Username,
			"project_name":        req.Auth.ProjectName,
			"domain_name":         req.Auth.DomainName,
			"user_domain_name":    req.Auth.UserDomainName,
			"project_domain_name": req.Auth.ProjectDomainName,
			"system_scope":        req.Auth.SystemScope,
			"is_admin":            fmt.Sprintf("%v", req.Auth.IsAdmin),
			"is_reader_admin":     fmt.Sprintf("%v", req.Auth.IsReaderAdmin),
		},
		Request: map[string]string{
			// Target fields
			"user_id":               req.Request.UserID,
			"project_id":            req.Request.ProjectID,
			"enforce_new_defaults":  req.Request.EnforceNewDefaults,
			"tenant":                req.Request.Tenant,
			"trust.trustor_user_id": req.Request.Trust.TrustorUserID,
			"member_id":             req.Request.MemberID,
			"owner":                 req.Request.Owner,
			"domain_id":             req.Request.DomainID,

			// Target fields
			"target.user.id":                 req.Request.Target.User.ID,
			"target.user.domain_id":          req.Request.Target.User.DomainID,
			"target.project.id":              req.Request.Target.Project.ID,
			"target.project.domain_id":       req.Request.Target.Project.DomainID,
			"target.trust.trustor_user_id":   req.Request.Target.TargetTrust.TrustorUserID,
			"target.trust.trustee_user_id":   req.Request.Target.TargetTrust.TrusteeUserID,
			"target.token.user_id":           req.Request.Target.Token.UserID,
			"target.domain.id":               req.Request.Target.Domain.ID,
			"target.domain_id":               req.Request.Target.TargetDomainID,
			"target.credential.user_id":      req.Request.Target.Credential.UserID,
			"target.role.domain_id":          req.Request.Target.Role.DomainID,
			"target.group.domain_id":         req.Request.Target.Group.DomainID,
			"target.limit.domain.id":         req.Request.Target.Limit.Domain.ID,
			"target.limit.project_id":        req.Request.Target.Limit.ProjectID,
			"target.limit.project.domain_id": req.Request.Target.Limit.Project.DomainID,
			"target.container.project_id":    req.Request.Target.Container.ProjectID,
			"target.secret.project_id":       req.Request.Target.Secret.ProjectID,
			"target.secret.creator_id":       req.Request.Target.Secret.CreatorID,
			"target.order.project_id":        req.Request.Target.Order.ProjectID,

			// Allocation fields
			"allocation.owner": req.Request.Allocation.Owner,

			// Node fields
			"node.lessee": req.Request.Node.Lessee,
			"node.owner":  req.Request.Node.Owner,
		},
		Roles: req.Auth.Roles,
	}

	// Enforce policy without any locking
	allowed := enforcer.Enforce(req.Action, ctx)

	// Log the policy decision with structured logging
	pm.logger.Info("policy decision",
		"action", req.Action,
		"user_id", req.Auth.UserID,
		"project_id", req.Auth.ProjectID,
		"allowed", allowed,
		"service", req.Service,
		"is_admin", req.Auth.IsAdmin,
		"roles", req.Auth.Roles,
	)

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(EnforceResponse{
		Allowed: allowed,
	}); err != nil {
		pm.logger.Error("failed to encode response", "error", err)
		return
	}
}

// Request represents the request context
type Request struct {
	UserID             string `json:"user_id"`
	ProjectID          string `json:"project_id"`
	EnforceNewDefaults string `json:"enforce_new_defaults"`
	Tenant             string `json:"tenant"`
	Trust              struct {
		TrustorUserID string `json:"trustor_user_id"`
	} `json:"trust"`
	Target struct {
		// Target fields
		User struct {
			ID       string `json:"id"`
			DomainID string `json:"domain_id"`
		} `json:"user"`
		Project struct {
			ID       string `json:"id"`
			DomainID string `json:"domain_id"`
		} `json:"project"`
		TargetTrust struct {
			TrustorUserID string `json:"trustor_user_id"`
			TrusteeUserID string `json:"trustee_user_id"`
		} `json:"trust"`
		Token struct {
			UserID string `json:"user_id"`
		} `json:"token"`
		Domain struct {
			ID string `json:"id"`
		} `json:"domain"`
		TargetDomainID string `json:"domain_id"`
		Credential     struct {
			UserID string `json:"user_id"`
		} `json:"credential"`
		Role struct {
			DomainID string `json:"domain_id"`
		} `json:"role"`
		Group struct {
			DomainID string `json:"domain_id"`
		} `json:"group"`
		Limit struct {
			Domain struct {
				ID string `json:"id"`
			} `json:"domain"`
			ProjectID string `json:"project_id"`
			Project   struct {
				DomainID string `json:"domain_id"`
			} `json:"project"`
		} `json:"limit"`
		Container struct {
			ProjectID string `json:"project_id"`
		} `json:"container"`
		Secret struct {
			ProjectID string `json:"project_id"`
			CreatorID string `json:"creator_id"`
		} `json:"secret"`
		Order struct {
			ProjectID string `json:"project_id"`
		} `json:"order"`
	} `json:"target"`

	Allocation Allocation `json:"allocation"`
	Node       Node       `json:"node"`
	MemberID   string     `json:"member_id"`
	Owner      string     `json:"owner"`
	DomainID   string     `json:"domain_id"`
}

// Allocation represents the allocation object in the request
type Allocation struct {
	Owner string `json:"owner"`
}

// Node represents the node object in the request
type Node struct {
	Lessee string `json:"lessee"`
	Owner  string `json:"owner"`
}

// EnforceRequest represents an authorization request
type EnforceRequest struct {
	Service string  `json:"service"`
	Action  string  `json:"rule"`
	Auth    Auth    `json:"credentials"`
	Request Request `json:"target"`
}

// EnforceResponse represents the authorization response
type EnforceResponse struct {
	Allowed bool   `json:"allowed"`
	Error   string `json:"error,omitempty"`
}

// Auth represents the authentication context from the keystone token
type Auth struct {
	UserID            string   `json:"user_id"`
	DomainID          string   `json:"domain_id"`
	ProjectID         string   `json:"project_id"`
	UserDomainID      string   `json:"user_domain_id"`
	ProjectDomainID   string   `json:"project_domain_id"`
	Username          string   `json:"username"`
	ProjectName       string   `json:"project_name"`
	DomainName        string   `json:"domain_name"`
	UserDomainName    string   `json:"user_domain_name"`
	ProjectDomainName string   `json:"project_domain_name"`
	SystemScope       string   `json:"system_scope"`
	IsAdmin           bool     `json:"is_admin"`
	IsReaderAdmin     bool     `json:"is_reader_admin"`
	Roles             []string `json:"roles"`
}
