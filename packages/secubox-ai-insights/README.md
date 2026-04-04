# SecuBox AI Insights

ML-based threat detection and security insights module for SecuBox-DEB.

## Features

- **Machine Learning Threat Detection**: Classification and scoring of security threats
- **Anomaly Detection**: Unsupervised detection of anomalies in network traffic
- **Log Analysis**: ML-powered analysis of security logs and events
- **Threat Scoring**: Risk assessment and classification by host/IP
- **Alert Correlation**: Pattern detection across multiple alert sources
- **Model Management**: Train and deploy custom ML models
- **Integration**: CrowdSec and Suricata alert ingestion

## Architecture

Three-fold architecture pattern:
- `/components` - System components description
- `/status` - Runtime health and metrics
- `/access` - Connection endpoints

## API Endpoints

### Health & Status
- `GET /health` - Service health check
- `GET /status` - Current metrics and status

### Configuration
- `GET /config` - Get current configuration
- `POST /config` - Update configuration

### Threats
- `GET /threats` - Current threat detections (supports filters)
- `GET /threats/history` - Historical threat data for trends

### Anomalies
- `GET /anomalies` - Detected anomalies

### Models
- `GET /models` - List loaded ML models
- `POST /model/train` - Train a new model
- `POST /model/deploy` - Deploy a trained model

### Scores & Analysis
- `GET /scores` - Threat scores by host/IP
- `GET /correlations` - Correlated alerts
- `GET /stats` - Detection statistics
- `POST /analyze` - Analyze specific log/event

### Integrations
- `GET /integrations` - CrowdSec/Suricata status
- `GET /logs` - Analysis logs

## Configuration

Configuration file: `/etc/secubox/ai-insights.toml`

```toml
[ai_insights]
detection_threshold = 0.7
anomaly_sensitivity = 0.8
auto_train = true
train_interval_hours = 24
crowdsec_integration = true
suricata_integration = true
max_correlations = 100
retention_days = 30
```

## Dashboard

Access the dashboard at: `https://<hostname>/ai-insights/`

Features:
- Real-time threat timeline
- Risk score gauges
- Model status cards
- Alert correlation graph
- Tabbed interface: Dashboard, Threats, Anomalies, Models, Correlations, Settings

## Installation

```bash
apt install secubox-ai-insights
```

## Service Management

```bash
systemctl status secubox-ai-insights
systemctl restart secubox-ai-insights
journalctl -u secubox-ai-insights -f
```

## Data Directories

- Models: `/var/lib/secubox/ai-insights/models/`
- Cache: `/var/cache/secubox/ai-insights/`
- History: `/var/lib/secubox/ai-insights/`

## Dependencies

- secubox-core (required)
- crowdsec (recommended)
- suricata (recommended)

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr | https://secubox.in
