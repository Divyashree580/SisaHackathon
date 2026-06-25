import React, { useEffect, useState, useRef } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import { RefreshCw, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react';

const API_BASE = 'http://localhost:8000/api';

// Fallback graph data if API is down
const FALLBACK_GRAPH = {
  nodes: [
    { id: "secure-login-update.com", type: "domain" },
    { id: "185.199.108.153", type: "ip" },
    { id: "LockBit", type: "malware" },
    { id: "FIN7", type: "malware" },
    { id: "CVE-2023-3519", type: "cve" },
  ],
  edges: [
    { source: "secure-login-update.com", target: "185.199.108.153" },
    { source: "185.199.108.153", target: "LockBit" },
    { source: "185.199.108.153", target: "FIN7" },
    { source: "LockBit", target: "CVE-2023-3519" },
    { source: "FIN7", target: "CVE-2023-3519" },
  ]
};

const NODE_COLORS = {
  domain: { bg: '#00f0ff', border: '#00b8d4', glow: 'rgba(0,240,255,0.4)' },
  ip: { bg: '#ffaa00', border: '#e69500', glow: 'rgba(255,170,0,0.4)' },
  malware: { bg: '#ff3e3e', border: '#cc2929', glow: 'rgba(255,62,62,0.4)' },
  cve: { bg: '#f000ff', border: '#c200cc', glow: 'rgba(240,0,255,0.4)' },
};

const NODE_LABELS = {
  domain: '🌐 Domain',
  ip: '🔢 IP Address',
  malware: '🦠 Malware',
  cve: '🛡️ CVE',
};

const CYTOSCAPE_STYLESHEET = [
  {
    selector: 'node',
    style: {
      'label': 'data(label)',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 10,
      'font-family': "'Inter', sans-serif",
      'font-size': '11px',
      'font-weight': 500,
      'color': '#f3f4f6',
      'text-outline-width': 2,
      'text-outline-color': '#0a0b10',
      'width': 50,
      'height': 50,
      'border-width': 3,
      'transition-property': 'border-width, width, height',
      'transition-duration': '0.2s',
    }
  },
  {
    selector: 'node[type="domain"]',
    style: {
      'background-color': NODE_COLORS.domain.bg,
      'border-color': NODE_COLORS.domain.border,
      'shape': 'diamond',
    }
  },
  {
    selector: 'node[type="ip"]',
    style: {
      'background-color': NODE_COLORS.ip.bg,
      'border-color': NODE_COLORS.ip.border,
      'shape': 'hexagon',
    }
  },
  {
    selector: 'node[type="malware"]',
    style: {
      'background-color': NODE_COLORS.malware.bg,
      'border-color': NODE_COLORS.malware.border,
      'shape': 'triangle',
    }
  },
  {
    selector: 'node[type="cve"]',
    style: {
      'background-color': NODE_COLORS.cve.bg,
      'border-color': NODE_COLORS.cve.border,
      'shape': 'round-rectangle',
    }
  },
  {
    selector: 'node:active, node:selected',
    style: {
      'border-width': 5,
      'width': 60,
      'height': 60,
    }
  },
  {
    selector: 'edge',
    style: {
      'width': 2,
      'line-color': 'rgba(255,255,255,0.15)',
      'target-arrow-color': 'rgba(255,255,255,0.3)',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'arrow-scale': 0.8,
      'transition-property': 'line-color, width',
      'transition-duration': '0.2s',
    }
  },
  {
    selector: 'edge:active, edge:selected',
    style: {
      'width': 4,
      'line-color': 'rgba(0,240,255,0.5)',
      'target-arrow-color': 'rgba(0,240,255,0.7)',
    }
  }
];

function convertToCytoscapeElements(graphData) {
  const elements = [];
  for (const node of graphData.nodes) {
    elements.push({
      data: { id: node.id, label: node.id, type: node.type }
    });
  }
  for (const edge of graphData.edges) {
    elements.push({
      data: { source: edge.source, target: edge.target }
    });
  }
  return elements;
}

export default function IocGraph() {
  const [graphData, setGraphData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [hoveredNode, setHoveredNode] = useState(null);
  const cyRef = useRef(null);

  useEffect(() => {
    const fetchGraph = async () => {
      try {
        const response = await fetch(`${API_BASE}/ioc/graph`);
        if (response.ok) {
          const data = await response.json();
          setGraphData(data);
        } else {
          throw new Error(`API error: ${response.status}`);
        }
      } catch (e) {
        console.warn('IOC graph API unavailable, using fallback:', e);
        setGraphData(FALLBACK_GRAPH);
      } finally {
        setLoading(false);
      }
    };
    fetchGraph();
  }, []);

  const handleCyReady = (cy) => {
    cyRef.current = cy;

    // Hover effects
    cy.on('mouseover', 'node', (e) => {
      const node = e.target;
      setHoveredNode({
        id: node.data('id'),
        type: node.data('type'),
        x: e.renderedPosition.x,
        y: e.renderedPosition.y,
      });
      node.style('border-width', 5);
      node.style('width', 60);
      node.style('height', 60);
      // Highlight connected edges
      node.connectedEdges().style({
        'width': 3,
        'line-color': 'rgba(0,240,255,0.5)',
        'target-arrow-color': 'rgba(0,240,255,0.7)',
      });
    });

    cy.on('mouseout', 'node', (e) => {
      const node = e.target;
      setHoveredNode(null);
      node.style('border-width', 3);
      node.style('width', 50);
      node.style('height', 50);
      node.connectedEdges().style({
        'width': 2,
        'line-color': 'rgba(255,255,255,0.15)',
        'target-arrow-color': 'rgba(255,255,255,0.3)',
      });
    });
  };

  const handleZoomIn = () => {
    if (cyRef.current) cyRef.current.zoom(cyRef.current.zoom() * 1.3);
  };
  const handleZoomOut = () => {
    if (cyRef.current) cyRef.current.zoom(cyRef.current.zoom() / 1.3);
  };
  const handleFit = () => {
    if (cyRef.current) cyRef.current.fit(undefined, 50);
  };
  const handleReset = () => {
    if (cyRef.current) {
      cyRef.current.layout({ name: 'cose', animate: true, animationDuration: 600 }).run();
      setTimeout(() => cyRef.current?.fit(undefined, 50), 700);
    }
  };

  if (loading) {
    return (
      <div className="card ioc-graph-loading">
        <div className="siem-loading-spinner">
          <div className="spinner" />
          <span>Loading IOC relationship graph…</span>
        </div>
      </div>
    );
  }

  const elements = graphData ? convertToCytoscapeElements(graphData) : [];

  return (
    <div className="ioc-graph-container animate-fade-in">
      <div className="card ioc-graph-card">
        <div className="ioc-graph-header">
          <div>
            <h2 className="card-title">IOC Relationship Graph</h2>
            <p className="card-subtitle">Interactive visualization of IOC connections and threat associations</p>
          </div>
          <div className="ioc-graph-controls">
            <button className="graph-ctrl-btn" onClick={handleZoomIn} title="Zoom In">
              <ZoomIn size={16} />
            </button>
            <button className="graph-ctrl-btn" onClick={handleZoomOut} title="Zoom Out">
              <ZoomOut size={16} />
            </button>
            <button className="graph-ctrl-btn" onClick={handleFit} title="Fit to View">
              <Maximize2 size={16} />
            </button>
            <button className="graph-ctrl-btn" onClick={handleReset} title="Reset Layout">
              <RefreshCw size={16} />
            </button>
          </div>
        </div>

        <div className="ioc-graph-viewport">
          <CytoscapeComponent
            elements={elements}
            stylesheet={CYTOSCAPE_STYLESHEET}
            layout={{
              name: 'cose',
              animate: true,
              animationDuration: 800,
              nodeRepulsion: () => 8000,
              idealEdgeLength: () => 120,
              gravity: 0.3,
              padding: 50,
            }}
            style={{ width: '100%', height: '100%', background: 'transparent' }}
            cy={(cy) => handleCyReady(cy)}
            userZoomingEnabled={true}
            userPanningEnabled={true}
            boxSelectionEnabled={false}
          />

          {/* Tooltip */}
          {hoveredNode && (
            <div
              className="ioc-graph-tooltip"
              style={{
                left: hoveredNode.x + 12,
                top: hoveredNode.y - 40,
              }}
            >
              <span className="tooltip-type" style={{ color: NODE_COLORS[hoveredNode.type]?.bg }}>
                {NODE_LABELS[hoveredNode.type] || hoveredNode.type}
              </span>
              <span className="tooltip-id">{hoveredNode.id}</span>
            </div>
          )}
        </div>

        {/* Legend */}
        <div className="ioc-graph-legend">
          {Object.entries(NODE_LABELS).map(([type, label]) => (
            <div className="legend-item" key={type}>
              <div className="legend-dot" style={{ backgroundColor: NODE_COLORS[type]?.bg, boxShadow: `0 0 8px ${NODE_COLORS[type]?.glow}` }} />
              <span>{label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
