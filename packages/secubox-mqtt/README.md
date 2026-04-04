# SecuBox MQTT

MQTT broker management module for SecuBox, wrapping Mosquitto.

## Features

- **Broker Control**: Start, stop, restart Mosquitto
- **Status Monitoring**: Real-time broker status and statistics via $SYS topics
- **Client Tracking**: View connected MQTT clients
- **Topic Monitoring**: View active topics with last values
- **User Management**: Add/remove MQTT users via `mosquitto_passwd`
- **ACL Management**: Configure topic access control rules
- **Configuration**: Web-based Mosquitto configuration

## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/status` | Broker status (running, clients, messages) |
| GET | `/health` | Health check |

### Protected Endpoints (JWT required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/clients` | Connected clients list |
| GET | `/topics` | Active topics |
| GET | `/stats` | Message statistics |
| POST | `/start` | Start mosquitto |
| POST | `/stop` | Stop mosquitto |
| POST | `/restart` | Restart mosquitto |
| GET | `/config` | Get mosquitto config |
| POST | `/config` | Update config |
| GET | `/users` | List MQTT users |
| POST | `/users` | Add user |
| DELETE | `/users/{username}` | Delete user |
| GET | `/acl` | Access control list |
| POST | `/acl` | Add ACL entry |
| DELETE | `/acl` | Delete ACL entry |
| GET | `/logs` | Mosquitto logs |

## Configuration Files

- `/etc/mosquitto/mosquitto.conf` - Main Mosquitto config
- `/etc/mosquitto/passwd` - User passwords (hashed)
- `/etc/mosquitto/acl` - Access control rules

## Dependencies

- `mosquitto` - Eclipse Mosquitto MQTT broker
- `mosquitto-clients` - mosquitto_sub/mosquitto_pub CLI tools
- `secubox-core` - SecuBox core library (JWT auth)

## Installation

```bash
apt install secubox-mqtt
```

## Service

The API runs as a systemd service:

```bash
systemctl status secubox-mqtt
systemctl restart secubox-mqtt
```

Unix socket: `/run/secubox/mqtt.sock`

## Frontend

Web UI available at `/mqtt/` with tabs:
- **Dashboard**: Status, stats, controls
- **Clients**: Connected client list
- **Topics**: Active topic tree
- **Users**: User management
- **Config**: Mosquitto configuration

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind - https://cybermind.fr
