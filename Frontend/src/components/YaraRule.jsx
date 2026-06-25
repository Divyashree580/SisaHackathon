import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { ClipboardCopy } from 'lucide-react';

export default function YaraRule() {
  const [rule, setRule] = useState(null);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const fetchRule = async () => {
      try {
        const data = await api.getYaraRule();
        setRule(data);
      } catch (e) {
        console.error('Failed to fetch YARA rule', e);
        setError('Unable to load rule');
      }
    };
    fetchRule();
  }, []);

  const handleCopy = () => {
    if (!rule) return;
    navigator.clipboard.writeText(JSON.stringify(rule, null, 2)).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  if (error) {
    return <div className="card error-card"><p>{error}</p></div>;
  }

  if (!rule) {
    return <div className="card loading-card"><p>Loading YARA rule...</p></div>;
  }

  return (
    <div className="card yara-rule-card">
      <div className="card-header flex justify-between items-center">
        <h2 className="card-title">YARA Rule Generation</h2>
        <button onClick={handleCopy} className="copy-btn" title="Copy to clipboard">
          <ClipboardCopy size={18} /> {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <pre className="yara-code" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
{JSON.stringify(rule, null, 2)}
      </pre>
    </div>
  );
}
