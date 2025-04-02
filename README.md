[![Build Status](https://github.com/mehmettopcu/goslo.policy.server/actions/workflows/go.yml/badge.svg?branch=master)](https://github.com/mehmettopcu/goslo.policy.server/actions/)

# OpenStack Oslo Policy Server

> **⚠️ Development Status**: This project is currently under active development. The API and features are subject to change. Please use with caution in production environments.

This project implements a centralized policy server for OpenStack Oslo policy rules. It provides a REST API for policy enforcement and supports dynamic policy updates through YAML configuration files.

> **Note**: This project is built on top of [goslo.policy](https://github.com/databus23/goslo.policy), a Go implementation of OpenStack's oslo.policy library.

## Features

- HTTP-based policy enforcement API
- YAML-based policy configuration
- Dynamic policy updates (no server restart required)
- Service-based policy management
- Token-based authentication support
- High-performance policy evaluation
- Graceful shutdown support
- Context-based server management
- Modern Go practices and optimizations

## Requirements

- Go 1.22 or later

## Installation

```bash
go get github.com/mehmettopcu/goslo.policy.server
```

## Usage

1. Create a policy directory and add your policy files:

```bash
mkdir -p policies
```

2. Add policy files for each service (e.g., `policies/nova-policy.yaml`):

```yaml
rules:
  compute:start_instance:
    description: "Only admin users can start instances"
    roles: ["admin"]
  
  compute:delete_instance:
    description: "Admin and project owner can delete instances"
    roles: ["admin"]
    allow_project_owner: true

  compute:resize_instance:
    description: "Only users with member or admin role can resize an instance"
    roles: ["admin", "member"]
```

3. Start the policy server:

```bash
go run main.go -policy-dir policies -addr :8080
```

The server will start and listen for policy enforcement requests. It supports graceful shutdown through SIGINT and SIGTERM signals.

4. Make policy enforcement requests:

```bash
curl -X POST http://localhost:8080/enforce \
  -H "Content-Type: application/json" \
  -d '{
    "service": "nova",
    "action": "compute:start_instance",
    "token": {
      "user": {
        "id": "123456",
        "name": "alice",
        "roles": ["admin"],
        "domain": "default"
      },
      "project": {
        "id": "7890",
        "name": "demo"
      }
    },
    "request": {
      "project_id": "7890"
    }
  }'
```

## API Reference

### POST /enforce

Enforces a policy rule for a given service and action.

#### Request Body

```json
{
  "service": "string",  // Service name (e.g., "nova")
  "action": "string",   // Action to enforce (e.g., "compute:start_instance")
  "token": {           // Token information
    "user": {
      "id": "string",
      "name": "string",
      "roles": ["string"],
      "domain": "string"
    },
    "project": {
      "id": "string",
      "name": "string"
    }
  },
  "request": {         // Request-specific information
    "project_id": "string"
  }
}
```

#### Response

```json
{
  "allowed": true|false,
  "error": "string"    // Optional error message
}
```

## Policy File Format

Each service should have its own YAML policy file in the policy directory. The file should be named `{service}-policy.yaml`.

### Policy Rule Format

```yaml
rules:
  action_name:
    description: "Human-readable description"
    roles: ["role1", "role2"]  # Required roles
    allow_project_owner: true   # Optional: allow project owner
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
