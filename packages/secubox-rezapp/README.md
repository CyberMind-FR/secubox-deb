# RezApp

Application deployment and management module for SecuBox.

**Category:** Apps

## Features

- Deploy containerized applications (Docker/LXC)
- Application templates (nginx, redis, postgres, etc.)
- Resource usage monitoring (CPU, memory, network)
- Container logs viewer
- Start/stop/restart applications
- Custom template creation

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-rezapp
```

## Prerequisites

- Docker installed and running
- Or LXC for container support

```bash
# Install Docker
sudo apt install docker.io

# Verify Docker is running
sudo systemctl status docker
```

## Configuration

Configuration directory: `/var/lib/secubox/rezapp/`

Custom templates: `/var/lib/secubox/rezapp/templates/`

## API Endpoints

### Health and Status

- `GET /api/v1/rezapp/health` - Health check
- `GET /api/v1/rezapp/status` - Module status

### Applications

- `GET /api/v1/rezapp/apps` - List all deployed apps
- `GET /api/v1/rezapp/app/{name}` - Get app details
- `POST /api/v1/rezapp/app/deploy` - Deploy new app
- `POST /api/v1/rezapp/app/undeploy` - Remove app
- `POST /api/v1/rezapp/app/{name}/start` - Start app
- `POST /api/v1/rezapp/app/{name}/stop` - Stop app
- `POST /api/v1/rezapp/app/{name}/restart` - Restart app
- `GET /api/v1/rezapp/app/{name}/logs` - Get app logs

### Templates

- `GET /api/v1/rezapp/templates` - List templates
- `GET /api/v1/rezapp/templates/{name}` - Get template
- `POST /api/v1/rezapp/templates` - Create custom template
- `DELETE /api/v1/rezapp/templates/{name}` - Delete custom template

### Images

- `GET /api/v1/rezapp/images` - List Docker images
- `POST /api/v1/rezapp/images/pull` - Pull Docker image

### Statistics

- `GET /api/v1/rezapp/stats` - Get cached statistics

## Built-in Templates

| Template  | Description                    | Default Ports |
|-----------|--------------------------------|---------------|
| nginx     | Nginx web server               | 80, 443       |
| redis     | Redis in-memory data store     | 6379          |
| postgres  | PostgreSQL database            | 5432          |
| mariadb   | MariaDB database               | 3306          |
| mongodb   | MongoDB NoSQL database         | 27017         |
| rabbitmq  | RabbitMQ message broker        | 5672, 15672   |
| minio     | MinIO S3-compatible storage    | 9000, 9001    |
| grafana   | Grafana monitoring dashboard   | 3000          |

## Example: Deploy an Application

```bash
# Using curl
curl -X POST http://localhost/api/v1/rezapp/app/deploy \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-nginx",
    "template": "nginx",
    "ports": {"8080": 80},
    "memory": "256m"
  }'
```

## Creating Custom Templates

```bash
curl -X POST http://localhost/api/v1/rezapp/templates \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-app",
    "description": "My custom application",
    "image": "myregistry/myapp:latest",
    "default_ports": {"8000": 8000},
    "default_memory": "512m",
    "default_cpus": 1.0
  }'
```

## License

MIT License - CyberMind (c) 2024-2026
