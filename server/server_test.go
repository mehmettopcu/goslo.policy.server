package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mehmettopcu/goslo.policy.server/log"
)

func setupTestPolicyDir(t interface{}) (string, func()) {
	// Create temporary directory for test policies
	tmpDir, err := os.MkdirTemp("", "policy-test-*")
	if err != nil {
		switch v := t.(type) {
		case *testing.T:
			v.Fatalf("Failed to create temp dir: %v", err)
		case *testing.B:
			v.Fatalf("Failed to create temp dir: %v", err)
		}
	}

	// Create test policy file
	policyContent := `"admin_required": "role:admin or is_admin:1"
"owner": "user_id:%(user_id)s"
"admin_or_owner": "rule:admin_required or rule:owner"
"compute:start_instance": "rule:admin_required"
"compute:delete_instance": "rule:admin_or_owner"
"compute:resize_instance": "role:admin or role:member"`

	if err := os.WriteFile(filepath.Join(tmpDir, "nova.yaml"), []byte(policyContent), 0644); err != nil {
		os.RemoveAll(tmpDir)
		switch v := t.(type) {
		case *testing.T:
			v.Fatalf("Failed to write test policy file: %v", err)
		case *testing.B:
			v.Fatalf("Failed to write test policy file: %v", err)
		}
	}

	// Return cleanup function
	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return tmpDir, cleanup
}

func TestNewPolicyServer(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "policy-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a simple policy file
	policyContent := `"test": "role:admin"`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.yaml"), []byte(policyContent), 0644); err != nil {
		t.Fatalf("Failed to write test policy file: %v", err)
	}

	// Create policy server with timeout
	done := make(chan bool)
	var ps *PolicyManager
	go func() {
		var err error
		ps, err = NewPolicyManager(tmpDir, log.GetLogger(), false)
		if err != nil {
			t.Errorf("Failed to create policy server: %v", err)
			done <- false
			return
		}
		if ps == nil {
			t.Error("Expected policy server to be created")
			done <- false
			return
		}
		done <- true
	}()

	select {
	case success := <-done:
		if !success {
			t.Fatal("Test failed")
		}
		// Shutdown the policy server
		ps.Shutdown()
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out")
	}
}

// TestHandleEnforce handles policy enforcement requests
func TestHandleEnforce(t *testing.T) {
	tmpDir, cleanup := setupTestPolicyDir(t)
	defer cleanup()

	ps, err := NewPolicyManager(tmpDir, log.GetLogger(), false)
	if err != nil {
		t.Fatalf("Failed to create policy server: %v", err)
	}
	defer ps.Shutdown()

	// Test cases
	tests := []struct {
		name           string
		request        EnforceRequest
		expectedStatus int
		expectedResult EnforceResponse
	}{
		{
			name: "Admin can start instance",
			request: EnforceRequest{
				Service: "nova",
				Action:  "compute:start_instance",
				Auth: Auth{
					UserID:   "123",
					DomainID: "default",
					IsAdmin:  true,
					Roles:    []string{"admin"},
				},
				Request: Request{
					UserID: "123",
				},
			},
			expectedStatus: http.StatusOK,
			expectedResult: EnforceResponse{
				Allowed: true,
			},
		},
		{
			name: "Non-admin cannot start instance",
			request: EnforceRequest{
				Service: "nova",
				Action:  "compute:start_instance",
				Auth: Auth{
					UserID:   "123",
					DomainID: "default",
					IsAdmin:  false,
					Roles:    []string{"member"},
				},
				Request: Request{
					UserID: "123",
				},
			},
			expectedStatus: http.StatusOK,
			expectedResult: EnforceResponse{
				Allowed: false,
			},
		},
		{
			name: "Owner can delete instance",
			request: EnforceRequest{
				Service: "nova",
				Action:  "compute:delete_instance",
				Auth: Auth{
					UserID:   "123",
					DomainID: "default",
					IsAdmin:  false,
					Roles:    []string{"member"},
				},
				Request: Request{
					UserID: "123",
				},
			},
			expectedStatus: http.StatusOK,
			expectedResult: EnforceResponse{
				Allowed: true,
			},
		},
		{
			name: "Member can resize instance",
			request: EnforceRequest{
				Service: "nova",
				Action:  "compute:resize_instance",
				Auth: Auth{
					UserID:        "123",
					DomainID:      "default",
					IsAdmin:       false,
					IsReaderAdmin: true,
					Roles:         []string{"member"},
				},
				Request: Request{
					UserID: "123",
				},
			},
			expectedStatus: http.StatusOK,
			expectedResult: EnforceResponse{
				Allowed: true,
			},
		},
		{
			name: "Invalid service",
			request: EnforceRequest{
				Service: "invalid-service",
				Action:  "compute:start_instance",
				Auth: Auth{
					UserID:   "123",
					DomainID: "default",
					IsAdmin:  true,
					Roles:    []string{"admin"},
				},
				Request: Request{
					UserID: "123",
				},
			},
			expectedStatus: http.StatusOK,
			expectedResult: EnforceResponse{
				Allowed: false,
				Error:   "Service invalid-service not found",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal request body
			body, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatalf("Failed to marshal request: %v", err)
			}

			// Create request with body
			req := httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			rr := httptest.NewRecorder()

			// Handle the request
			ps.HandleEnforce(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %v, got %v", tt.expectedStatus, rr.Code)
			}

			// Check response body
			var response EnforceResponse
			if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if response.Allowed != tt.expectedResult.Allowed {
				t.Errorf("Expected allowed %v, got %v", tt.expectedResult.Allowed, response.Allowed)
			}

			if response.Error != tt.expectedResult.Error {
				t.Errorf("Expected error %v, got %v", tt.expectedResult.Error, response.Error)
			}
		})
	}
}

func TestPolicyReload(t *testing.T) {
	tmpDir, cleanup := setupTestPolicyDir(t)
	defer cleanup()

	ps, err := NewPolicyManager(tmpDir, log.GetLogger(), true)
	if err != nil {
		t.Fatalf("Failed to create policy server: %v", err)
	}
	defer ps.Shutdown()

	// Wait for initial load
	time.Sleep(1000 * time.Millisecond)
	t.Log("Initial policy loaded")

	// First verify that member cannot start instance (initial policy)
	req := EnforceRequest{
		Service: "nova",
		Action:  "compute:start_instance",
		Auth: Auth{
			UserID:   "123",
			DomainID: "default",
			IsAdmin:  false,
			Roles:    []string{"member"},
		},
		Request: Request{
			UserID: "123",
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	httpReq := httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	ps.HandleEnforce(rr, httpReq)

	// Debug logs
	t.Logf("Response Status: %d", rr.Code)
	t.Logf("Response Body: %s", rr.Body.String())

	var response EnforceResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	t.Logf("Initial policy check - Response: %+v", response)
	if response.Allowed {
		t.Error("Expected request to be denied before policy reload")
	}

	// Update policy file with new content that allows members to start instances
	newPolicyContent := `"admin_required": "role:admin or is_admin:1"
"owner": "user_id:%(user_id)s"
"admin_or_owner": "rule:admin_required or rule:owner"
"compute:start_instance": "role:member"
"compute:delete_instance": "rule:admin_or_owner"
"compute:resize_instance": "role:admin or role:member"`

	policyFile := filepath.Join(tmpDir, "nova.yaml")
	if err := os.WriteFile(policyFile, []byte(newPolicyContent), 0644); err != nil {
		t.Fatalf("Failed to update test policy file: %v", err)
	}
	t.Log("Updated policy file written")

	// Wait for reload to complete
	time.Sleep(1000 * time.Millisecond)

	// Verify that member can now start instance (after policy reload)
	// Create a new request for the second check
	body, err = json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}
	httpReq = httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	rr = httptest.NewRecorder()
	ps.HandleEnforce(rr, httpReq)

	// Debug logs
	t.Logf("Response Status: %d", rr.Code)
	t.Logf("Response Body: %s", rr.Body.String())

	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	t.Logf("After policy reload - Response: %+v", response)
	if !response.Allowed {
		t.Error("Expected request to be allowed after policy reload")
	}
}

func TestInvalidRequests(t *testing.T) {
	tmpDir, cleanup := setupTestPolicyDir(t)
	defer cleanup()

	ps, err := NewPolicyManager(tmpDir, log.GetLogger(), false)
	if err != nil {
		t.Fatalf("Failed to create policy server: %v", err)
	}

	tests := []struct {
		name           string
		method         string
		body           string
		expectedStatus int
		expectedResult EnforceResponse
	}{
		{
			name:           "Invalid HTTP method",
			method:         "GET",
			body:           "{}",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedResult: EnforceResponse{
				Allowed: false,
				Error:   "Method not allowed",
			},
		},
		{
			name:           "Invalid JSON",
			method:         "POST",
			body:           "{invalid json}",
			expectedStatus: http.StatusBadRequest,
			expectedResult: EnforceResponse{
				Allowed: false,
				Error:   "Invalid request body",
			},
		},
		{
			name:           "Missing user in token",
			method:         "POST",
			body:           `{"service":"nova","action":"compute:start_instance","token":{},"request":{}}`,
			expectedStatus: http.StatusOK,
			expectedResult: EnforceResponse{
				Allowed: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/enforce", bytes.NewBufferString(tt.body))
			if tt.method == "POST" {
				req.Header.Set("Content-Type", "application/json")
			}

			rr := httptest.NewRecorder()
			ps.HandleEnforce(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %v, got %v", tt.expectedStatus, rr.Code)
			}

			var response EnforceResponse
			if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if response.Allowed != tt.expectedResult.Allowed {
				t.Errorf("Expected allowed %v, got %v", tt.expectedResult.Allowed, response.Allowed)
			}

			if response.Error != tt.expectedResult.Error {
				t.Errorf("Expected error %v, got %v", tt.expectedResult.Error, response.Error)
			}
		})
	}
}

func BenchmarkHandleEnforce(b *testing.B) {
	tmpDir, cleanup := setupTestPolicyDir(b)
	defer cleanup()

	ps, err := NewPolicyManager(tmpDir, log.GetLogger(), false)
	if err != nil {
		b.Fatalf("Failed to create policy server: %v", err)
	}
	defer ps.Shutdown()

	// Create a test request
	req := EnforceRequest{
		Service: "nova",
		Action:  "compute:start_instance",
		Auth: Auth{
			UserID:   "123",
			DomainID: "default",
			IsAdmin:  true,
		},
		Request: Request{
			UserID: "123",
		},
	}

	// Marshal request body
	body, err := json.Marshal(req)
	if err != nil {
		b.Fatalf("Failed to marshal request: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		httpReq := httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(body))
		httpReq.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		ps.HandleEnforce(rr, httpReq)
	}
}

func BenchmarkPolicyReload(b *testing.B) {
	tmpDir, cleanup := setupTestPolicyDir(b)
	defer cleanup()

	ps, err := NewPolicyManager(tmpDir, log.GetLogger(), true)
	if err != nil {
		b.Fatalf("Failed to create policy server: %v", err)
	}
	defer ps.Shutdown()

	// Create a new policy content
	newPolicyContent := `"admin_required": "role:admin or is_admin:1"
"owner": "user_id:%(user_id)s"
"admin_or_owner": "rule:admin_required or rule:owner"
"compute:start_instance": "role:member"
"compute:delete_instance": "rule:admin_or_owner"
"compute:resize_instance": "role:admin or role:member"`

	policyFile := filepath.Join(tmpDir, "nova.yaml")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Write new policy content
		if err := os.WriteFile(policyFile, []byte(newPolicyContent), 0644); err != nil {
			b.Fatalf("Failed to write policy file: %v", err)
		}

		// Write back original content
		if err := os.WriteFile(policyFile, []byte(`"admin_required": "role:admin or is_admin:1"
"owner": "user_id:%(user_id)s"
"admin_or_owner": "rule:admin_required or rule:owner"
"compute:start_instance": "rule:admin_required"
"compute:delete_instance": "rule:admin_or_owner"
"compute:resize_instance": "role:admin or role:member"`), 0644); err != nil {
			b.Fatalf("Failed to write policy file: %v", err)
		}
	}
}

func BenchmarkConcurrentEnforce(b *testing.B) {
	tmpDir, cleanup := setupTestPolicyDir(b)
	defer cleanup()

	ps, err := NewPolicyManager(tmpDir, log.GetLogger(), true)
	if err != nil {
		b.Fatalf("Failed to create policy server: %v", err)
	}
	defer ps.Shutdown()

	// Create a test request
	req := EnforceRequest{
		Service: "nova",
		Action:  "compute:start_instance",
		Auth: Auth{
			UserID:   "123",
			DomainID: "default",
			IsAdmin:  true,
			Roles:    []string{"admin"},
		},
		Request: Request{
			UserID: "123",
		},
	}

	// Marshal request body
	body, err := json.Marshal(req)
	if err != nil {
		b.Fatalf("Failed to marshal request: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Create HTTP request
			httpReq := httptest.NewRequest("POST", "/enforce", bytes.NewBuffer(body))
			httpReq.Header.Set("Content-Type", "application/json")

			// Create response recorder
			rr := httptest.NewRecorder()

			// Handle the request
			ps.HandleEnforce(rr, httpReq)

			// Check response
			if rr.Code != http.StatusOK {
				b.Errorf("Expected status %v, got %v", http.StatusOK, rr.Code)
			}

			var response EnforceResponse
			if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
				b.Fatalf("Failed to decode response: %v", err)
			}

			if !response.Allowed {
				b.Error("Expected request to be allowed")
			}
		}
	})
}
