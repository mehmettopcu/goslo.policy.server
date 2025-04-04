# OpenStack Oslo Policy Server

[![Build Status](https://github.com/mehmettopcu/goslo.policy.server/actions/workflows/docker.yml/badge.svg?branch=main)](https://github.com/mehmettopcu/goslo.policy.server/actions/)

> **⚠️ Development Status**: This project is currently under active development. The API and features are subject to change. Please use with caution in production environments.

This project implements a centralized policy server for OpenStack Oslo policy rules. It provides a REST API for policy enforcement and supports dynamic policy updates through YAML configuration files.

> **Note**: This project is built on top of [goslo.policy](https://github.com/databus23/goslo.policy), a Go implementation of OpenStack's oslo.policy library.

> **Integration**: This server is designed to work seamlessly with [oslo.policy.remote](https://github.com/mehmettopcu/oslo.policy.remote), which provides a Python client for remote policy enforcement. Together, they enable distributed policy enforcement across your OpenStack services.

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

1.Create a policy directory and add your policy files:

```bash
  mkdir -p policy-files
```

2.Add policy files for each service (e.g., `policy-files/nova.yaml`):

  ```yaml
  "context_is_admin": "role:admin"
  "admin_or_owner": "is_admin:True or project_id:%(project_id)s"
  "admin_api": "is_admin:True"
  "project_member_api": "role:member and project_id:%(project_id)s"
  "project_reader_api": "role:reader and project_id:%(project_id)s"
  "project_member_or_admin": "rule:project_member_api or rule:context_is_admin"
  "project_reader_or_admin": "rule:project_reader_api or rule:context_is_admin"
  "os_compute_api:os-admin-actions:reset_state": "rule:context_is_admin"
  "os_compute_api:os-admin-actions:inject_network_info": "rule:context_is_admin"
  ```

3.Start the policy server:

```bash
go run main.go -policy-dir policy-files -addr :8082
```

The server will start and listen for policy enforcement requests. It supports graceful shutdown through SIGINT and SIGTERM signals.

4.Make policy enforcement requests:

```bash
curl -s -X POST http://policy-server:8082/enforce \
  -H "Content-Type: application/json" \
  -d '{
    "service": "nova",
    "rule": "os_compute_api:servers:detail",
    "credentials": {
        "user_id": "123456",
        "project_id": "7890",
        "roles": ["admin"]
    },
    "target": {
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
  "rule": "string",   // Action to enforce (e.g., "compute:start_instance")
  "credentials": {           // Token information
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
  "target": {         // Request-specific information
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

Each service should have its own YAML policy file in the policy directory. The file should be named `{service}.yaml`.

### Policy Rule Format

<https://docs.openstack.org/oslo.policy/latest/admin/policy-yaml-file.html>

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

The Apache License 2.0 is a permissive free software license written by the Apache Software Foundation (ASF). It allows users to:

- Use the software for any purpose
- Distribute the software
- Modify the software
- Distribute modified versions of the software

For more information about the Apache License 2.0, please visit:

- [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [Apache License FAQ](https://www.apache.org/foundation/license-faq.html)
