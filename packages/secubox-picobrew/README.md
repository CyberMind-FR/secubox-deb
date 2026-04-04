# SecuBox PicoBrew - Fermentation Controller

SecuBox-DEB Phase 9 IoT module for homebrewing and fermentation temperature control.

## Features

- **Temperature Monitoring**: Support for DS18B20 (1-Wire), DHT22, BME280 (I2C), Tilt, iSpindel sensors
- **Fermentation Profiles**: Define multi-step temperature schedules with ramp times
- **Session Tracking**: Log entire fermentation sessions with continuous temperature recording
- **Recipe Management**: Store and organize brewing recipes with target gravities
- **Temperature Alerts**: Get notified when temperature deviates from target

## API Endpoints

### Health & Status
- `GET /api/v1/picobrew/health` - Health check
- `GET /api/v1/picobrew/status` - System overview

### Sensors
- `GET /api/v1/picobrew/sensors` - List all sensors
- `GET /api/v1/picobrew/sensors/detect` - Detect hardware sensors
- `POST /api/v1/picobrew/sensors` - Add a sensor
- `GET /api/v1/picobrew/sensors/{id}` - Get sensor details
- `DELETE /api/v1/picobrew/sensors/{id}` - Remove sensor
- `POST /api/v1/picobrew/sensors/{id}/reading` - Add manual reading

### Profiles
- `GET /api/v1/picobrew/profiles` - List fermentation profiles
- `GET /api/v1/picobrew/profile/{name}` - Get profile details
- `POST /api/v1/picobrew/profile/add` - Create profile
- `DELETE /api/v1/picobrew/profile/{name}` - Delete profile
- `GET /api/v1/picobrew/profiles/builtin` - List built-in profiles
- `POST /api/v1/picobrew/profiles/import/{name}` - Import built-in profile

### Sessions
- `GET /api/v1/picobrew/sessions` - List all sessions
- `GET /api/v1/picobrew/session/{id}` - Get session details
- `POST /api/v1/picobrew/session/start` - Start new session
- `POST /api/v1/picobrew/session/{id}/end` - End session
- `DELETE /api/v1/picobrew/session/{id}` - Delete session
- `GET /api/v1/picobrew/session/{id}/readings` - Get session temperature history

### Recipes
- `GET /api/v1/picobrew/recipes` - List all recipes
- `GET /api/v1/picobrew/recipe/{name}` - Get recipe details
- `POST /api/v1/picobrew/recipe/add` - Add recipe
- `DELETE /api/v1/picobrew/recipe/{name}` - Delete recipe

### Alerts
- `GET /api/v1/picobrew/alerts` - List alerts
- `POST /api/v1/picobrew/alerts/{id}/acknowledge` - Acknowledge alert
- `DELETE /api/v1/picobrew/alerts/{id}` - Delete alert
- `POST /api/v1/picobrew/alerts/clear` - Clear acknowledged alerts

### Configuration
- `GET /api/v1/picobrew/config` - Get configuration
- `POST /api/v1/picobrew/config` - Update configuration

## Supported Sensors

### DS18B20 (1-Wire)
- Hardware address auto-detection via `/sys/bus/w1/devices/28-*`
- Enable 1-Wire in `/boot/config.txt`: `dtoverlay=w1-gpio`

### DHT22 / BME280 (I2C)
- Auto-detection at I2C addresses 0x76, 0x77
- Enable I2C in `/boot/config.txt`: `dtparam=i2c_arm=on`

### Tilt Hydrometer (Bluetooth)
- BLE temperature and gravity monitoring
- Requires Bluetooth enabled on the board

### iSpindel
- WiFi-based hydrometer
- Configure iSpindel to POST to `/api/v1/picobrew/sensors/{id}/reading`

## Built-in Fermentation Profiles

1. **Ale Standard** - Standard ale at 18-20C with cold crash
2. **Lager Classic** - Traditional lager with 4-week cold conditioning
3. **Belgian Saison** - Warm fermentation ramping to 30C
4. **Cold Crash** - Quick 3-day cold crash

## Configuration

Configuration file: `/etc/secubox/picobrew.toml`

```toml
poll_interval = 30      # Sensor polling interval in seconds
temp_unit = "C"         # Temperature unit: C or F
alert_threshold = 2.0   # Degrees deviation before alert
```

## Data Storage

- Sensors: `/var/lib/secubox/picobrew/sensors/`
- Profiles: `/var/lib/secubox/picobrew/profiles/`
- Sessions: `/var/lib/secubox/picobrew/sessions/`
- Recipes: `/var/lib/secubox/picobrew/recipes/`
- Alerts: `/var/lib/secubox/picobrew/alerts/`
- Cache: `/var/cache/secubox/picobrew/`

## Build

```bash
cd packages/secubox-picobrew
dpkg-buildpackage -us -uc -b
```

## Service Management

```bash
# Start/stop/restart
systemctl start secubox-picobrew
systemctl stop secubox-picobrew
systemctl restart secubox-picobrew

# Check status
systemctl status secubox-picobrew

# View logs
journalctl -u secubox-picobrew -f
```

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind - https://cybermind.fr
