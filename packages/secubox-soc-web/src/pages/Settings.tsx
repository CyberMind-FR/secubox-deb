/**
 * SecuBox SOC - Settings Page
 * Configure hierarchical mode and enrollment
 */

import { useState } from 'react';
import { Settings as SettingsIcon, Globe, MapPin, Server, Save, Key, Link } from 'lucide-react';

interface HierarchyStatus {
  mode: string;
  region_id?: string;
  region_name?: string;
  has_upstream?: boolean;
  upstream_url?: string;
  accept_regional?: boolean;
  regional_socs_count?: number;
}

interface SettingsProps {
  hierarchy: HierarchyStatus;
  onUpdate: () => void;
}

export default function Settings({ hierarchy, onUpdate }: SettingsProps) {
  const [mode, setMode] = useState(hierarchy.mode);
  const [regionId, setRegionId] = useState(hierarchy.region_id || '');
  const [regionName, setRegionName] = useState(hierarchy.region_name || '');
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: string; text: string } | null>(null);

  // Enrollment state
  const [enrollToken, setEnrollToken] = useState('');
  const [centralUrl, setCentralUrl] = useState('');
  const [enrolling, setEnrolling] = useState(false);

  // Token generation state
  const [tokenRegionId, setTokenRegionId] = useState('');
  const [tokenRegionName, setTokenRegionName] = useState('');
  const [generatedToken, setGeneratedToken] = useState('');
  const [generating, setGenerating] = useState(false);

  const saveMode = async () => {
    setSaving(true);
    setMessage(null);

    try {
      const token = localStorage.getItem('jwt_token');
      const res = await fetch('/api/v1/soc-gateway/hierarchy/mode', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          mode,
          region_id: regionId,
          region_name: regionName
        })
      });

      if (res.ok) {
        setMessage({ type: 'success', text: 'Mode updated successfully' });
        onUpdate();
      } else {
        const data = await res.json();
        setMessage({ type: 'error', text: data.detail || 'Failed to update mode' });
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'Network error' });
    } finally {
      setSaving(false);
    }
  };

  const enrollWithCentral = async () => {
    if (!centralUrl || !enrollToken) return;

    setEnrolling(true);
    setMessage(null);

    try {
      const token = localStorage.getItem('jwt_token');
      const res = await fetch('/api/v1/soc-gateway/upstream/enroll', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          central_url: centralUrl,
          enrollment_token: enrollToken
        })
      });

      if (res.ok) {
        setMessage({ type: 'success', text: 'Enrolled with central SOC successfully' });
        setEnrollToken('');
        onUpdate();
      } else {
        const data = await res.json();
        setMessage({ type: 'error', text: data.detail || 'Enrollment failed' });
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'Network error' });
    } finally {
      setEnrolling(false);
    }
  };

  const generateToken = async () => {
    if (!tokenRegionId || !tokenRegionName) return;

    setGenerating(true);
    setMessage(null);

    try {
      const token = localStorage.getItem('jwt_token');
      const res = await fetch('/api/v1/soc-gateway/regional/token', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          region_id: tokenRegionId,
          region_name: tokenRegionName,
          ttl_minutes: 1440
        })
      });

      if (res.ok) {
        const data = await res.json();
        setGeneratedToken(data.token);
        setMessage({ type: 'success', text: 'Token generated (valid 24h)' });
      } else {
        const data = await res.json();
        setMessage({ type: 'error', text: data.detail || 'Failed to generate token' });
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'Network error' });
    } finally {
      setGenerating(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setMessage({ type: 'success', text: 'Copied to clipboard' });
  };

  return (
    <div className="page settings-page">
      <header className="page-header">
        <h1><SettingsIcon size={28} /> SOC Settings</h1>
      </header>

      {message && (
        <div className={`message ${message.type}`}>
          {message.text}
        </div>
      )}

      {/* Mode Configuration */}
      <section className="settings-section">
        <h2>Hierarchical Mode</h2>
        <p className="section-description">
          Configure this gateway's role in the SOC hierarchy.
        </p>

        <div className="mode-selector">
          <label className={`mode-option ${mode === 'central' ? 'selected' : ''}`}>
            <input
              type="radio"
              name="mode"
              value="central"
              checked={mode === 'central'}
              onChange={(e) => setMode(e.target.value)}
            />
            <Globe size={24} />
            <span className="mode-name">Central</span>
            <span className="mode-desc">Top of hierarchy, accepts regional SOCs</span>
          </label>

          <label className={`mode-option ${mode === 'regional' ? 'selected' : ''}`}>
            <input
              type="radio"
              name="mode"
              value="regional"
              checked={mode === 'regional'}
              onChange={(e) => setMode(e.target.value)}
            />
            <MapPin size={24} />
            <span className="mode-name">Regional</span>
            <span className="mode-desc">Aggregates edge nodes, reports to central</span>
          </label>

          <label className={`mode-option ${mode === 'edge' ? 'selected' : ''}`}>
            <input
              type="radio"
              name="mode"
              value="edge"
              checked={mode === 'edge'}
              onChange={(e) => setMode(e.target.value)}
            />
            <Server size={24} />
            <span className="mode-name">Edge</span>
            <span className="mode-desc">Standalone, no upstream connection</span>
          </label>
        </div>

        {mode === 'regional' && (
          <div className="region-config">
            <div className="form-group">
              <label>Region ID</label>
              <input
                type="text"
                value={regionId}
                onChange={(e) => setRegionId(e.target.value)}
                placeholder="e.g., eu-west, paris, datacenter-1"
              />
            </div>
            <div className="form-group">
              <label>Region Name</label>
              <input
                type="text"
                value={regionName}
                onChange={(e) => setRegionName(e.target.value)}
                placeholder="e.g., Europe West, Paris DC"
              />
            </div>
          </div>
        )}

        <button className="btn-primary" onClick={saveMode} disabled={saving}>
          <Save size={16} />
          {saving ? 'Saving...' : 'Save Mode'}
        </button>
      </section>

      {/* Regional: Enroll with Central */}
      {mode === 'regional' && (
        <section className="settings-section">
          <h2><Link size={20} /> Connect to Central SOC</h2>
          <p className="section-description">
            Enter the central SOC URL and enrollment token to connect.
          </p>

          <div className="form-group">
            <label>Central SOC URL</label>
            <input
              type="text"
              value={centralUrl}
              onChange={(e) => setCentralUrl(e.target.value)}
              placeholder="https://central-soc.example.com"
            />
          </div>
          <div className="form-group">
            <label>Enrollment Token</label>
            <input
              type="text"
              value={enrollToken}
              onChange={(e) => setEnrollToken(e.target.value)}
              placeholder="Token from central SOC"
            />
          </div>

          <button
            className="btn-primary"
            onClick={enrollWithCentral}
            disabled={enrolling || !centralUrl || !enrollToken}
          >
            <Link size={16} />
            {enrolling ? 'Enrolling...' : 'Enroll with Central'}
          </button>

          {hierarchy.has_upstream && (
            <div className="status-info success">
              ✓ Connected to upstream: {hierarchy.upstream_url}
            </div>
          )}
        </section>
      )}

      {/* Central: Generate Regional Tokens */}
      {mode === 'central' && (
        <section className="settings-section">
          <h2><Key size={20} /> Generate Regional Token</h2>
          <p className="section-description">
            Create enrollment tokens for regional SOCs to connect.
          </p>

          <div className="form-row">
            <div className="form-group">
              <label>Region ID</label>
              <input
                type="text"
                value={tokenRegionId}
                onChange={(e) => setTokenRegionId(e.target.value)}
                placeholder="e.g., eu-west"
              />
            </div>
            <div className="form-group">
              <label>Region Name</label>
              <input
                type="text"
                value={tokenRegionName}
                onChange={(e) => setTokenRegionName(e.target.value)}
                placeholder="e.g., Europe West"
              />
            </div>
          </div>

          <button
            className="btn-primary"
            onClick={generateToken}
            disabled={generating || !tokenRegionId || !tokenRegionName}
          >
            <Key size={16} />
            {generating ? 'Generating...' : 'Generate Token'}
          </button>

          {generatedToken && (
            <div className="token-display">
              <label>Enrollment Token (valid 24h):</label>
              <code onClick={() => copyToClipboard(generatedToken)}>
                {generatedToken}
              </code>
              <small>Click to copy</small>
            </div>
          )}

          {hierarchy.regional_socs_count !== undefined && (
            <div className="status-info">
              Connected Regional SOCs: {hierarchy.regional_socs_count}
            </div>
          )}
        </section>
      )}

      <style>{`
        .settings-page {
          padding: 1.5rem;
          max-width: 800px;
        }

        .page-header h1 {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          margin-bottom: 1.5rem;
        }

        .message {
          padding: 0.75rem 1rem;
          border-radius: 6px;
          margin-bottom: 1.5rem;
        }

        .message.success {
          background: rgba(46, 204, 113, 0.15);
          border: 1px solid var(--status-online);
          color: var(--status-online);
        }

        .message.error {
          background: rgba(231, 76, 60, 0.15);
          border: 1px solid var(--alert-critical);
          color: var(--alert-critical);
        }

        .settings-section {
          background: var(--bg-secondary);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 1.5rem;
          margin-bottom: 1.5rem;
        }

        .settings-section h2 {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          margin: 0 0 0.5rem 0;
        }

        .section-description {
          color: var(--text-muted);
          margin-bottom: 1.5rem;
        }

        .mode-selector {
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          margin-bottom: 1.5rem;
        }

        .mode-option {
          display: flex;
          align-items: center;
          gap: 1rem;
          padding: 1rem;
          background: var(--bg-primary);
          border: 2px solid var(--border-color);
          border-radius: 8px;
          cursor: pointer;
          transition: all 0.2s;
        }

        .mode-option:hover {
          border-color: var(--cyber-cyan);
        }

        .mode-option.selected {
          border-color: var(--cyber-cyan);
          background: rgba(0, 212, 255, 0.1);
        }

        .mode-option input {
          display: none;
        }

        .mode-name {
          font-weight: bold;
          font-size: 1.1rem;
        }

        .mode-desc {
          color: var(--text-muted);
          font-size: 0.9rem;
          margin-left: auto;
        }

        .region-config {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 1rem;
          margin-bottom: 1.5rem;
        }

        .form-group {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .form-group label {
          font-weight: 500;
          color: var(--text-muted);
        }

        .form-group input {
          padding: 0.75rem;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: var(--bg-primary);
          color: var(--text-primary);
          font-size: 1rem;
        }

        .form-group input:focus {
          outline: none;
          border-color: var(--cyber-cyan);
        }

        .form-row {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 1rem;
          margin-bottom: 1rem;
        }

        .btn-primary {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.75rem 1.5rem;
          background: var(--cyber-cyan);
          color: var(--cosmos-black);
          border: none;
          border-radius: 6px;
          font-weight: bold;
          cursor: pointer;
          transition: all 0.2s;
        }

        .btn-primary:hover:not(:disabled) {
          background: var(--matrix-green);
        }

        .btn-primary:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .token-display {
          margin-top: 1rem;
          padding: 1rem;
          background: var(--bg-primary);
          border-radius: 6px;
        }

        .token-display label {
          display: block;
          color: var(--text-muted);
          margin-bottom: 0.5rem;
        }

        .token-display code {
          display: block;
          padding: 0.75rem;
          background: var(--cosmos-black);
          border-radius: 4px;
          font-family: monospace;
          word-break: break-all;
          cursor: pointer;
          color: var(--cyber-cyan);
        }

        .token-display small {
          display: block;
          margin-top: 0.5rem;
          color: var(--text-muted);
        }

        .status-info {
          margin-top: 1rem;
          padding: 0.75rem;
          background: var(--bg-primary);
          border-radius: 6px;
          color: var(--text-muted);
        }

        .status-info.success {
          color: var(--status-online);
        }

        @media (max-width: 600px) {
          .region-config,
          .form-row {
            grid-template-columns: 1fr;
          }

          .mode-desc {
            display: none;
          }
        }
      `}</style>
    </div>
  );
}
