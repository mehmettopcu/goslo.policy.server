package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/mehmettopcu/goslo.policy.server/log"
	"github.com/mehmettopcu/goslo.policy.server/policy"
)

// PolicyFile represents a single policy file configuration
type PolicyFile struct {
	Name        string
	Path        string
	LastUpdated time.Time
	Enforcer    *policy.Enforcer
	koanf       *koanf.Koanf
}

// PolicyManager handles policy file management and caching
type PolicyManager struct {
	policyDir  string
	policies   map[string]*PolicyFile // Map for faster access
	mu         sync.RWMutex           // Mutex for thread-safe access
	watcher    *fsnotify.Watcher
	logger     *log.CustomLogger
	wg         sync.WaitGroup
	reloadChan chan string   // Channel for managing reloads
	stopChan   chan struct{} // Channel for graceful shutdown
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

// NewPolicyManager creates a new policy manager instance
func NewPolicyManager(dir string, logger *log.CustomLogger, watchFiles bool) (*PolicyManager, error) {
	// Create watcher if file watching is enabled
	var watcher *fsnotify.Watcher
	var err error
	if watchFiles {
		watcher, err = fsnotify.NewWatcher()
		if err != nil {
			return nil, fmt.Errorf("failed to create watcher: %v", err)
		}
	}

	pm := &PolicyManager{
		policyDir:  dir,
		policies:   make(map[string]*PolicyFile),
		watcher:    watcher,
		logger:     logger,
		reloadChan: make(chan string, 10), // Reduced buffer size
		stopChan:   make(chan struct{}),
	}

	// Load initial policies
	if err := pm.loadAllPolicies(watchFiles); err != nil {
		return nil, err
	}

	// Start watching for policy changes if enabled
	if watchFiles {
		pm.wg.Add(1)
		go pm.watchPolicyDir()
		pm.wg.Add(1)
		go pm.handleReloads()
	}

	return pm, nil
}

// loadAllPolicies loads all policy files from the directory
func (pm *PolicyManager) loadAllPolicies(watchFiles bool) error {
	// Add policy directory to watcher if enabled
	if watchFiles && pm.watcher != nil {
		if err := pm.watcher.Add(pm.policyDir); err != nil {
			return fmt.Errorf("failed to add policy directory to watcher: %v", err)
		}
	}

	// Walk through the policy directory
	return filepath.Walk(pm.policyDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		pm.loadPolicyFile(path, watchFiles)
		return nil
	})
}

// loadPolicyFile loads a single policy file
func (pm *PolicyManager) loadPolicyFile(path string, watchFiles bool) {
	// Get service name from file path
	serviceName := filepath.Base(path)
	serviceName = serviceName[:len(serviceName)-len(filepath.Ext(serviceName))]

	// Check if file is already loaded
	pm.mu.RLock()
	if _, exists := pm.policies[serviceName]; exists {
		pm.mu.RUnlock()
		pm.logger.Info("file already loaded", "service", serviceName, "path", path)
		return
	}
	pm.mu.RUnlock()

	// Create a new Koanf instance
	k := koanf.New(".")

	// Create file provider
	f := file.Provider(path)

	// Load YAML file
	if err := k.Load(f, yaml.Parser()); err != nil {
		pm.logger.Error("failed to load config file",
			"service", serviceName,
			"path", path,
			"error", err,
		)
		return
	}

	// Unmarshal rules
	var rules map[string]string
	if err := k.Unmarshal("", &rules); err != nil {
		pm.logger.Error("failed to unmarshal rules",
			"service", serviceName,
			"path", path,
			"error", err,
		)
		return
	}

	// Create enforcer
	enforcer, err := policy.NewEnforcer(rules)
	if err != nil {
		pm.logger.Error("failed to create enforcer",
			"service", serviceName,
			"path", path,
			"error", err,
		)
		return
	}

	// Store policy file
	pm.mu.Lock()
	pm.policies[serviceName] = &PolicyFile{
		Name:        serviceName,
		Path:        path,
		LastUpdated: time.Now(),
		Enforcer:    enforcer,
		koanf:       k,
	}
	pm.mu.Unlock()

	// Start watching this file if enabled
	if watchFiles && pm.watcher != nil {
		pm.wg.Add(1)
		go pm.watchFile(serviceName, k, f)
	}

	pm.logger.Info("loaded policy file", "service", serviceName, "path", path)
}

// watchFile monitors a single policy file for changes
func (pm *PolicyManager) watchFile(serviceName string, _ *koanf.Koanf, f *file.File) {
	defer pm.wg.Done()

	if err := f.Watch(func(event interface{}, err error) {
		if err != nil {
			pm.logger.Error("watch error", "service", serviceName, "error", err)
			return
		}

		select {
		case <-pm.stopChan:
			return
		default:
			// Send reload request to channel
			select {
			case pm.reloadChan <- serviceName:
				pm.logger.Debug("reload request sent", "service", serviceName)
			default:
				pm.logger.Warn("reload channel full, skipping update", "service", serviceName)
			}
		}
	}); err != nil {
		pm.logger.Error("failed to start file watcher", "service", serviceName, "error", err)
		return
	}

	// Wait for stop signal
	<-pm.stopChan
}

// handleReloads processes reload requests
func (pm *PolicyManager) handleReloads() {
	defer pm.wg.Done()

	for {
		select {
		case serviceName := <-pm.reloadChan:
			// Get policy file
			pm.mu.RLock()
			policyFile, exists := pm.policies[serviceName]
			pm.mu.RUnlock()

			if !exists {
				pm.logger.Error("policy file not found", "service", serviceName)
				continue
			}

			// Reload policy
			if err := pm.reloadPolicy(serviceName, policyFile.koanf, file.Provider(policyFile.Path)); err != nil {
				pm.logger.Error("failed to reload policy",
					"service", serviceName,
					"error", err,
				)
			} else {
				pm.logger.Info("policy reloaded successfully", "service", serviceName)
			}

		case <-pm.stopChan:
			pm.logger.Debug("handleReloads received stop signal")
			return
		}
	}
}

// reloadPolicy reloads a policy file
func (pm *PolicyManager) reloadPolicy(serviceName string, k *koanf.Koanf, f *file.File) error {
	// Load YAML file
	if err := k.Load(f, yaml.Parser()); err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	// Unmarshal rules
	var rules map[string]string
	if err := k.Unmarshal("", &rules); err != nil {
		return fmt.Errorf("failed to unmarshal rules: %w", err)
	}

	// Create enforcer
	enforcer, err := policy.NewEnforcer(rules)
	if err != nil {
		return fmt.Errorf("failed to create enforcer: %w", err)
	}

	// Update policy file
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if policyFile, exists := pm.policies[serviceName]; exists {
		policyFile.Enforcer = enforcer
		policyFile.LastUpdated = time.Now()
		pm.logger.Info("reloaded policy file", "service", serviceName)
	} else {
		return fmt.Errorf("policy file not found: %s", serviceName)
	}

	return nil
}

// watchPolicyDir monitors the policy directory for new files
func (pm *PolicyManager) watchPolicyDir() {
	defer pm.wg.Done()

	for {
		select {
		case event, ok := <-pm.watcher.Events:
			if !ok {
				return
			}

			if event.Op&fsnotify.Create == fsnotify.Create {
				if filepath.Ext(event.Name) == ".yaml" || filepath.Ext(event.Name) == ".yml" {
					pm.logger.Info("new policy file detected", "path", event.Name)
					pm.loadPolicyFile(event.Name, true)
				}
			}
		case err, ok := <-pm.watcher.Errors:
			if !ok {
				return
			}
			pm.logger.Error("watcher error", "error", err)
		case <-pm.stopChan:
			return
		}
	}
}

// GetPolicy retrieves a policy enforcer for a service
func (pm *PolicyManager) GetPolicy(service string) (*policy.Enforcer, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if policyFile, exists := pm.policies[service]; exists {
		return policyFile.Enforcer, true
	}
	return nil, false
}

// Shutdown gracefully stops the policy manager
func (pm *PolicyManager) Shutdown() {
	pm.logger.Info("shutting down policy manager")

	// Signal all goroutines to stop
	close(pm.stopChan)
	close(pm.reloadChan)

	// Close watcher
	if pm.watcher != nil {
		if err := pm.watcher.Close(); err != nil {
			pm.logger.Error("failed to close watcher", "error", err)
		}
	}

	// Wait for all goroutines to finish
	pm.wg.Wait()

	pm.logger.Info("policy manager shutdown complete")
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
		pm.logger.Info("service not found", "service", req.Service)
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
	pm.logger.Info("audit",
		"service", req.Service,
		"allowed", allowed,
		"action", req.Action,
		"user_id", req.Auth.UserID,
		"project_id", req.Auth.ProjectID,
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

func (pm *PolicyManager) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		pm.logger.Error("failed to write health response", "error", err)
	}
}
