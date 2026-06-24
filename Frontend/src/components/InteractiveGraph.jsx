import React, { useState, useEffect } from 'react';
import { Network, Server, Globe, ShieldAlert, Shield, Hash, Info, Award, User } from 'lucide-react';

export default function InteractiveGraph({ analysisData }) {
  const [nodes, setNodes] = useState([]);
  const [links, setLinks] = useState([]);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    if (!analysisData) return;

    const newNodes = [];
    const newLinks = [];

    // 1. Center node (Threat Incident)
    const centerNode = {
      id: 'center',
      label: analysisData.risk_level + ' Incident',
      type: 'threat',
      x: 350,
      y: 200,
      radius: 28,
      color: analysisData.risk_level === 'Critical' ? '#ff3e3e' : analysisData.risk_level === 'High' ? '#ffaa00' : '#00f0ff'
    };
    newNodes.push(centerNode);

    let angle = 0;
    const actorName = analysisData.enrichment?.threat_actors?.[0];
    const malwareName = analysisData.enrichment?.malware_families?.[0];
    const cveName = analysisData.enrichment?.cve_id && analysisData.enrichment.cve_id !== 'N/A' ? analysisData.enrichment.cve_id : null;

    // Collect related components
    const satellites = [];

    if (actorName) {
      satellites.push({ id: 'actor', label: actorName, type: 'actor', radius: 22, color: '#f000ff' });
    }
    if (malwareName) {
      satellites.push({ id: 'malware', label: malwareName, type: 'malware', radius: 22, color: '#ffaa00' });
    }
    if (cveName) {
      satellites.push({ id: 'cve', label: cveName, type: 'cve', radius: 22, color: '#ff3e3e' });
    }

    // Add IOC Satellites
    analysisData.iocs?.forEach((ioc, index) => {
      let color = '#00f0ff';
      if (ioc.reputation === 'Malicious') color = '#ff3e3e';
      else if (ioc.reputation === 'Suspicious') color = '#ffaa00';
      else if (ioc.reputation?.includes('Scanner')) color = '#00ff9f';

      satellites.push({
        id: `ioc-${index}`,
        label: ioc.value,
        type: ioc.type,
        radius: 18,
        color: color,
        details: ioc.context
      });
    });

    // Arrange satellites in a circle around center
    const totalSatellites = satellites.length;
    const distance = 160;

    satellites.forEach((sat, index) => {
      const theta = (index / totalSatellites) * 2 * Math.PI;
      sat.x = centerNode.x + distance * Math.cos(theta);
      sat.y = centerNode.y + distance * Math.sin(theta);
      
      newNodes.push(sat);

      // Create links from center to satellite
      newLinks.push({
        source: 'center',
        target: sat.id,
        id: `link-c-${sat.id}`,
        color: sat.color
      });

      // Secondary links
      if (sat.id === 'malware' && satellites.some(s => s.id === 'actor')) {
        newLinks.push({ source: 'actor', target: 'malware', id: 'link-act-mal', color: '#f000ff', dashed: true });
      }
      if (sat.id === 'malware' && satellites.some(s => s.id === 'cve')) {
        newLinks.push({ source: 'cve', target: 'malware', id: 'link-cve-mal', color: '#ff3e3e', dashed: true });
      }
    });

    setNodes(newNodes);
    setLinks(newLinks);
    setSelectedNode(null);
  }, [analysisData]);

  const getNodeIcon = (type) => {
    switch (type?.toLowerCase()) {
      case 'threat':
        return ShieldAlert;
      case 'actor':
        return User;
      case 'malware':
        return Award;
      case 'cve':
      case 'cve id':
        return Shield;
      case 'ipv4':
        return Server;
      case 'domain':
      case 'url':
        return Globe;
      default:
        return Info;
    }
  };

  if (!analysisData) {
    return (
      <div className="graph-card card empty">
        <p>Run threat analysis to view the threat interaction graph.</p>
      </div>
    );
  }

  return (
    <div className="graph-card card">
      <div className="card-header">
        <h2>Adversarial Relationship Graph</h2>
        <span className="card-subtitle">IOC network paths and actor attribution relationship map</span>
      </div>

      <div className="graph-viewport-container">
        {/* SVG Graph Viewport */}
        <div className="graph-svg-wrapper">
          <svg className="graph-svg" viewBox="0 0 700 400" width="100%" height="100%">
            {/* Draw Links */}
            {links.map((link) => {
              const srcNode = nodes.find(n => n.id === link.source);
              const tgtNode = nodes.find(n => n.id === link.target);
              if (!srcNode || !tgtNode) return null;

              const isHighlighted = hoveredNode && (hoveredNode.id === link.source || hoveredNode.id === link.target);

              return (
                <line
                  key={link.id}
                  x1={srcNode.x}
                  y1={srcNode.y}
                  x2={tgtNode.x}
                  y2={tgtNode.y}
                  stroke={link.color}
                  strokeWidth={isHighlighted ? 3 : 1.5}
                  strokeOpacity={isHighlighted ? 0.9 : 0.4}
                  strokeDasharray={link.dashed ? "5,5" : "none"}
                  className={isHighlighted ? "link-pulse" : ""}
                />
              );
            })}

            {/* Draw Nodes */}
            {nodes.map((node) => {
              const Icon = getNodeIcon(node.type);
              const isCenter = node.id === 'center';
              const isHovered = hoveredNode?.id === node.id;
              const isSelected = selectedNode?.id === node.id;

              return (
                <g 
                  key={node.id} 
                  className={`graph-node-group ${isCenter ? 'center-node' : ''}`}
                  transform={`translate(${node.x}, ${node.y})`}
                  onMouseEnter={() => setHoveredNode(node)}
                  onMouseLeave={() => setHoveredNode(null)}
                  onClick={() => setSelectedNode(node)}
                  style={{ cursor: 'pointer' }}
                >
                  {/* Glowing Ring */}
                  <circle
                    r={node.radius + (isHovered ? 8 : 4)}
                    fill="none"
                    stroke={node.color}
                    strokeWidth={2}
                    strokeOpacity={isHovered || isSelected ? 0.8 : 0.2}
                    className={isHovered || isCenter ? "pulse-ring" : ""}
                  />

                  {/* Base Circle */}
                  <circle
                    r={node.radius}
                    fill="#151722"
                    stroke={node.color}
                    strokeWidth={isHovered || isSelected ? 3 : 2}
                  />

                  {/* Icon */}
                  <foreignObject 
                    x={-10} 
                    y={-10} 
                    width={20} 
                    height={20} 
                    style={{ pointerEvents: 'none' }}
                  >
                    <Icon size={20} style={{ color: node.color }} />
                  </foreignObject>

                  {/* Text Label */}
                  <text
                    y={node.radius + 15}
                    textAnchor="middle"
                    fill={isHovered ? '#fff' : '#8a99ad'}
                    fontSize={11}
                    className="node-label font-mono"
                  >
                    {node.label.length > 20 ? `${node.label.slice(0, 18)}...` : node.label}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Graph Details Sidebar */}
        <div className="graph-details-panel font-sans">
          <h3>Entity Context Inspector</h3>
          {selectedNode ? (
            <div className="entity-details animate-fade-in">
              <div className="entity-header">
                <span className="badge" style={{ backgroundColor: selectedNode.color, color: '#16171d' }}>
                  {selectedNode.type.toUpperCase()}
                </span>
                <h4 className="font-mono">{selectedNode.label}</h4>
              </div>
              <div className="entity-meta-info">
                <p><strong>Status:</strong> Active Indicator</p>
                {selectedNode.details && (
                  <p><strong>Attribution Context:</strong> {selectedNode.details}</p>
                )}
                <p><strong>Position:</strong> X: {selectedNode.x.toFixed(0)}, Y: {selectedNode.y.toFixed(0)}</p>
              </div>
            </div>
          ) : hoveredNode ? (
            <div className="entity-details animate-fade-in">
              <div className="entity-header">
                <span className="badge" style={{ backgroundColor: hoveredNode.color, color: '#16171d' }}>
                  {hoveredNode.type.toUpperCase()}
                </span>
                <h4 className="font-mono">{hoveredNode.label}</h4>
              </div>
              <p className="hover-tip">Click entity node to pin detailed inspection profile.</p>
            </div>
          ) : (
            <div className="graph-inspector-empty">
              <Network size={32} className="network-icon" />
              <p>Hover or click on any node in the topology map to inspect metadata links and network relations.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
