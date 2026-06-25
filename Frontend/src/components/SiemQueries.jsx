import React, { useEffect, useState } from 'react';
import { ClipboardCopy, Check, Database, Search, Server } from 'lucide-react';

const API_BASE = 'http://localhost:8000/api';

// Fallback queries generator if API is down
const generateSiemQueries = (domain, ip) => {
  return {
    splunk: `index=proxy (url="*${domain}*" OR dest_ip="${ip}")
| stats count by src_ip, url, dest_ip
| sort -count`,
    kql: `CommonSecurityLog
| where DestinationHostName contains "${domain}" or DestinationIP == "${ip}"
| summarize Count=count() by SourceIP, DestinationHostName`,
    elastic: `{
  "query": {
    "bool": {
      "should": [
        { "match": { "url.domain": "${domain}" } },
        { "match": { "destination.ip": "${ip}" } }
      ]
    }
  }
}`
  };
};

const PLATFORM_META = {
  splunk: {
    label: 'Splunk SPL',
    icon: Search,
    color: '#00C853',
    gradient: 'linear-gradient(135deg, rgba(0,200,83,0.12), rgba(0,200,83,0.03))',
    borderColor: 'rgba(0,200,83,0.25)',
  },
  kql: {
    label: 'Microsoft Sentinel KQL',
    icon: Database,
    color: '#448AFF',
    gradient: 'linear-gradient(135deg, rgba(68,138,255,0.12), rgba(68,138,255,0.03))',
    borderColor: 'rgba(68,138,255,0.25)',
  },
  elastic: {
    label: 'Elastic DSL',
    icon: Server,
    color: '#FF9100',
    gradient: 'linear-gradient(135deg, rgba(255,145,0,0.12), rgba(255,145,0,0.03))',
    borderColor: 'rgba(255,145,0,0.25)',
  }
};

function QueryBlock({ platform, query }) {
  const [copied, setCopied] = useState(false);
  const meta = PLATFORM_META[platform];
  const Icon = meta.icon;

  const handleCopy = () => {
    navigator.clipboard.writeText(query).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="siem-query-block" style={{ background: meta.gradient, borderColor: meta.borderColor }}>
      <div className="siem-query-header">
        <div className="siem-platform-label" style={{ color: meta.color }}>
          <Icon size={16} />
          <span>{meta.label}</span>
        </div>
        <button
          className="siem-copy-btn"
          onClick={handleCopy}
          title="Copy query to clipboard"
          style={{ color: copied ? '#00ff9f' : 'var(--text-secondary)' }}
        >
          {copied ? <Check size={14} /> : <ClipboardCopy size={14} />}
          <span>{copied ? 'Copied!' : 'Copy'}</span>
        </button>
      </div>
      <pre className="siem-query-code">{query}</pre>
    </div>
  );
}

export default function SiemQueries({ activeAnalysis = null }) {
  const [queries, setQueries] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Extract domain and IP from activeAnalysis
  const iocs = activeAnalysis?.iocs || [];
  const foundDomain = iocs.find(ioc => ioc.type === 'Domain')?.value || 
                      iocs.find(ioc => ioc.type === 'URL')?.value || 
                      '';
  const foundIp = iocs.find(ioc => ioc.type === 'IPv4')?.value || '';

  // Clean domain if it's a URL
  let cleanDomain = foundDomain;
  if (cleanDomain && (cleanDomain.startsWith('http://') || cleanDomain.startsWith('https://'))) {
    try {
      cleanDomain = new URL(cleanDomain).hostname;
    } catch (e) {
      // Ignore URL parsing errors
    }
  }

  const domain = cleanDomain || 'secure-login-update.com';
  const ip = foundIp || '185.199.108.153';

  useEffect(() => {
    const fetchQueries = async () => {
      setLoading(true);
      try {
        const queryParams = new URLSearchParams();
        if (domain) queryParams.append('domain', domain);
        if (ip) queryParams.append('ip', ip);
        
        const response = await fetch(`${API_BASE}/siem/queries?${queryParams.toString()}`);
        if (response.ok) {
          const data = await response.json();
          setQueries(data);
        } else {
          throw new Error(`API error: ${response.status}`);
        }
      } catch (e) {
        console.warn('SIEM API unavailable, using fallback:', e);
        setQueries(generateSiemQueries(domain, ip));
      } finally {
        setLoading(false);
      }
    };
    fetchQueries();
  }, [domain, ip]);

  if (loading) {
    return (
      <div className="card siem-loading-card">
        <div className="siem-loading-spinner">
          <div className="spinner" />
          <span>Generating SIEM queries…</span>
        </div>
      </div>
    );
  }

  if (error) {
    return <div className="card error-card"><p>{error}</p></div>;
  }

  return (
    <div className="siem-queries-container animate-fade-in">
      <div className="card siem-header-card">
        <div className="card-header">
          <h2 className="card-title">SIEM Query Generation</h2>
          <p className="card-subtitle">Auto-generated detection queries for major SIEM platforms based on extracted IOCs</p>
        </div>

        {/* Raw input context */}
        {activeAnalysis?.raw_input && (
          <div style={{
            margin: '0 0 16px 0',
            padding: '14px 18px',
            backgroundColor: 'var(--bg-primary)',
            borderLeft: '4px solid var(--color-medium)',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.875rem',
            color: 'var(--text-secondary)',
            lineHeight: '1.6',
          }}>
            <span style={{
              display: 'block',
              fontSize: '0.7rem',
              fontWeight: '700',
              color: 'var(--color-medium)',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              marginBottom: '6px',
            }}>
              📥 Threat Input
            </span>
            <span style={{ fontStyle: 'italic', color: 'var(--text-primary)' }}>
              "{activeAnalysis.raw_input}"
            </span>
          </div>
        )}

        <div className="siem-ioc-context">
          <div className="siem-ioc-chip">
            <span className="siem-ioc-type">Domain Target</span>
            <code>{domain}</code>
          </div>
          <div className="siem-ioc-chip">
            <span className="siem-ioc-type">IP Target</span>
            <code>{ip}</code>
          </div>
        </div>
      </div>

      <div className="siem-queries-grid">
        {queries && Object.entries(queries).map(([platform, query]) => (
          <QueryBlock key={platform} platform={platform} query={query} />
        ))}
      </div>
    </div>
  );
}
