import React, { useState, useEffect, useRef } from 'react';
import { 
  Network, Server, Globe, ShieldAlert, Shield, Hash, 
  Info, Award, User, RefreshCw, Layers 
} from 'lucide-react';
import * as d3 from 'd3';

export default function InteractiveGraph({ analysisData }) {
  const [nodes, setNodes] = useState([]);
  const [links, setLinks] = useState([]);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [activeFilter, setActiveFilter] = useState('all'); // 'all' | 'intel' | 'network' | 'file'
  const [resetTrigger, setResetTrigger] = useState(0);
  const [draggedNodeId, setDraggedNodeId] = useState(null);
  const simulationRef = useRef(null);

  // Initialize and run D3 force simulation
  useEffect(() => {
    if (!analysisData) return;

    const newNodes = [];
    const newLinks = [];

    // 1. Center Node (Threat Incident)
    const centerNode = {
      id: 'center',
      label: analysisData.risk_level + ' Incident',
      type: 'threat',
      x: 350,
      y: 200,
      radius: 30,
      color: analysisData.risk_level === 'Critical' ? '#ff3e3e' : analysisData.risk_level === 'High' ? '#ffaa00' : '#00f0ff'
    };
    newNodes.push(centerNode);

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

    // Arrange satellites in a circle around center as starting coordinates for simulation
    const totalSatellites = satellites.length;
    const initialDistance = 150;

    satellites.forEach((sat, index) => {
      const theta = (index / totalSatellites) * 2 * Math.PI;
      sat.x = centerNode.x + initialDistance * Math.cos(theta);
      sat.y = centerNode.y + initialDistance * Math.sin(theta);
      
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

    // Filter nodes based on activeFilter
    const filteredNodes = newNodes.filter(node => {
      if (node.id === 'center') return true;
      if (activeFilter === 'all') return true;
      if (activeFilter === 'intel') {
        return ['actor', 'malware', 'cve', 'cve id', 'threat'].includes(node.type?.toLowerCase());
      }
      if (activeFilter === 'network') {
        return ['ipv4', 'domain', 'url', 'email'].includes(node.type?.toLowerCase());
      }
      if (activeFilter === 'file') {
        return ['md5', 'sha1', 'sha256'].includes(node.type?.toLowerCase());
      }
      return true;
    });

    const filteredNodeIds = new Set(filteredNodes.map(n => n.id));
    const filteredLinks = newLinks.filter(link => 
      filteredNodeIds.has(link.source) && filteredNodeIds.has(link.target)
    );

    // Setup D3 Force Simulation
    const simulation = d3.forceSimulation(filteredNodes)
      .force('link', d3.forceLink(filteredLinks).id(d => d.id).distance(130).strength(1))
      .force('charge', d3.forceManyBody().strength(-350))
      .force('center', d3.forceCenter(350, 200))
      .force('collision', d3.forceCollide().radius(d => d.radius + 15))
      .alphaDecay(0.04); // Moderate decay for smooth stabilization

    simulationRef.current = simulation;

    // Update state on each tick
    simulation.on('tick', () => {
      setNodes([...filteredNodes]);
      setLinks([...filteredLinks]);
    });

    setSelectedNode(null);

    return () => {
      simulation.stop();
    };
  }, [analysisData, resetTrigger, activeFilter]);

  // Pointer dragging handlers
  const handlePointerDown = (e, nodeId) => {
    e.stopPropagation();
    e.currentTarget.setPointerCapture(e.pointerId);
    setDraggedNodeId(nodeId);

    // Heat up simulation
    if (simulationRef.current) {
      simulationRef.current.alphaTarget(0.3).restart();
    }

    // Fix node position
    setNodes(prev => prev.map(node => {
      if (node.id === nodeId) {
        node.fx = node.x;
        node.fy = node.y;
      }
      return node;
    }));
  };

  const handlePointerMove = (e) => {
    if (!draggedNodeId) return;
    const svg = e.currentTarget;
    const rect = svg.getBoundingClientRect();
    
    // Convert client coordinates to SVG viewBox (700 x 400)
    const x = ((e.clientX - rect.left) / rect.width) * 700;
    const y = ((e.clientY - rect.top) / rect.height) * 400;

    // Clamp values so nodes don't get dragged off-screen
    const clampedX = Math.min(680, Math.max(20, x));
    const clampedY = Math.min(380, Math.max(20, y));

    setNodes(prev => prev.map(node => {
      if (node.id === draggedNodeId) {
        node.fx = clampedX;
        node.fy = clampedY;
        node.x = clampedX;
        node.y = clampedY;
      }
      return node;
    }));
  };

  const handlePointerUp = (e) => {
    if (draggedNodeId) {
      if (simulationRef.current) {
        simulationRef.current.alphaTarget(0);
      }
      setNodes(prev => prev.map(node => {
        if (node.id === draggedNodeId) {
          node.fx = null;
          node.fy = null;
        }
        return node;
      }));
      setDraggedNodeId(null);
    }
  };

  const handleResetLayout = () => {
    setResetTrigger(prev => prev + 1);
  };

  const getNodeIcon = (type) => {
    switch (type?.toLowerCase()) {
      case 'threat': return ShieldAlert;
      case 'actor': return User;
      case 'malware': return Award;
      case 'cve':
      case 'cve id': return Shield;
      case 'ipv4': return Server;
      case 'domain':
      case 'url': return Globe;
      default: return Info;
    }
  };

  const getNodeFill = (node) => {
    if (node.id === 'center') return 'url(#grad-threat)';
    if (node.type === 'actor') return 'url(#grad-actor)';
    if (node.type === 'malware') return 'url(#grad-malware)';
    if (node.type === 'cve') return 'url(#grad-cve)';
    
    // IOC Node Fills based on color mapping
    if (node.color === '#ff3e3e') return 'url(#grad-ioc-mal)';
    if (node.color === '#ffaa00') return 'url(#grad-ioc-susp)';
    if (node.color === '#00ff9f') return 'url(#grad-ioc-low)';
    return 'url(#grad-ioc-default)';
  };

  if (!analysisData) {
    return (
      <div className="graph-card card empty">
        <div style={{ textAlign: 'center', padding: '60px 20px' }}>
          <Network size={48} className="text-muted animate-pulse" style={{ marginBottom: '16px' }} />
          <h3>System Awaiting Ingestion</h3>
          <p style={{ color: 'var(--text-secondary)', marginTop: '8px' }}>Run a threat analysis scan to view the interactive relationship topology map.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="graph-card card">
      {/* Top Header Control Bar */}
      <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h2>Adversarial Relationship Graph</h2>
          <span className="card-subtitle">IOC network paths and actor attribution relationship map</span>
        </div>
        
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          {/* Snap Reset Button */}
          <button 
            onClick={handleResetLayout} 
            className="btn btn-secondary btn-icon-only btn-small"
            title="Stabilize & Reset Node Positions"
            style={{ padding: '8px' }}
          >
            <RefreshCw size={14} />
          </button>

          {/* Graph Filters Row */}
          <div className="graph-filters-row">
            <button 
              className={`filter-btn ${activeFilter === 'all' ? 'active' : ''}`}
              onClick={() => { setActiveFilter('all'); setSelectedNode(null); }}
            >
              All Nodes
            </button>
            <button 
              className={`filter-btn ${activeFilter === 'intel' ? 'active' : ''}`}
              onClick={() => { setActiveFilter('intel'); setSelectedNode(null); }}
            >
              Attribution
            </button>
            <button 
              className={`filter-btn ${activeFilter === 'network' ? 'active' : ''}`}
              onClick={() => { setActiveFilter('network'); setSelectedNode(null); }}
            >
              Network
            </button>
            <button 
              className={`filter-btn ${activeFilter === 'file' ? 'active' : ''}`}
              onClick={() => { setActiveFilter('file'); setSelectedNode(null); }}
            >
              Signatures
            </button>
          </div>
        </div>
      </div>

      {/* Threat Input Context box */}
      <div className="analysis-input-context animate-fade-in" style={{
        margin: '0 24px 16px 24px',
        padding: '12px 16px',
        backgroundColor: 'var(--bg-primary)',
        borderLeft: '4px solid var(--color-medium)',
        borderRadius: 'var(--radius-sm)',
        fontSize: '0.85rem',
        color: 'var(--text-secondary)',
        lineHeight: '1.4'
      }}>
        <span style={{ 
          display: 'block', 
          fontSize: '0.75rem', 
          fontWeight: '700', 
          color: 'var(--color-medium)',
          textTransform: 'uppercase', 
          letterSpacing: '0.05em', 
          marginBottom: '4px' 
        }}>
          Threat Graph Context:
        </span>
        "{analysisData.raw_input || 'N/A'}"
      </div>

      <div className="graph-viewport-container">
        {/* SVG Graph Viewport */}
        <div className="graph-svg-wrapper">
          <span className="drag-hint font-mono text-muted" style={{ position: 'absolute', top: '10px', left: '10px', fontSize: '0.7rem' }}>
            * Click and drag nodes to custom positions
          </span>
          <svg 
            className="graph-svg" 
            viewBox="0 0 700 400" 
            width="100%" 
            height="100%"
            onPointerMove={handlePointerMove}
            onPointerUp={handlePointerUp}
            onPointerLeave={handlePointerUp}
          >
            {/* Gradient Definitions */}
            <defs>
              <linearGradient id="grad-threat" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#ff5e62" />
                <stop offset="100%" stopColor="#ff3e3e" />
              </linearGradient>
              <linearGradient id="grad-actor" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#f000ff" />
                <stop offset="100%" stopColor="#7b00ff" />
              </linearGradient>
              <linearGradient id="grad-malware" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#ffaa00" />
                <stop offset="100%" stopColor="#ff5500" />
              </linearGradient>
              <linearGradient id="grad-cve" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#ff3e3e" />
                <stop offset="100%" stopColor="#ffaa00" />
              </linearGradient>
              <linearGradient id="grad-ioc-mal" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#ff3e3e" />
                <stop offset="100%" stopColor="#a30000" />
              </linearGradient>
              <linearGradient id="grad-ioc-susp" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#ffaa00" />
                <stop offset="100%" stopColor="#b37400" />
              </linearGradient>
              <linearGradient id="grad-ioc-low" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#00ff9f" />
                <stop offset="100%" stopColor="#00a365" />
              </linearGradient>
              <linearGradient id="grad-ioc-default" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#00f0ff" />
                <stop offset="100%" stopColor="#007799" />
              </linearGradient>
              
              <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="5" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            {/* Draw Links */}
            {links.map((link) => {
              const srcNode = typeof link.source === 'object' ? link.source : nodes.find(n => n.id === link.source);
              const tgtNode = typeof link.target === 'object' ? link.target : nodes.find(n => n.id === link.target);
              if (!srcNode || !tgtNode) return null;

              const srcId = srcNode.id;
              const tgtId = tgtNode.id;
              const isHighlighted = hoveredNode && (hoveredNode.id === srcId || hoveredNode.id === tgtId);

              return (
                <g key={link.id}>
                  {/* Base static background line */}
                  <line
                    x1={srcNode.x}
                    y1={srcNode.y}
                    x2={tgtNode.x}
                    y2={tgtNode.y}
                    stroke={link.color}
                    strokeWidth={isHighlighted ? 4 : 1.5}
                    strokeOpacity={isHighlighted ? 0.3 : 0.15}
                  />
                  {/* Animated dotted flow overlay line */}
                  <line
                    x1={srcNode.x}
                    y1={srcNode.y}
                    x2={tgtNode.x}
                    y2={tgtNode.y}
                    stroke={link.color}
                    strokeWidth={isHighlighted ? 2.5 : 1.2}
                    strokeOpacity={isHighlighted ? 0.95 : 0.6}
                    strokeDasharray={link.dashed ? "5,5" : "6,6"}
                    className="link-pulse"
                  />
                </g>
              );
            })}

            {/* Draw Nodes */}
            {nodes.map((node) => {
              const Icon = getNodeIcon(node.type);
              const isCenter = node.id === 'center';
              const isHovered = hoveredNode?.id === node.id;
              const isSelected = selectedNode?.id === node.id;
              const isDragging = draggedNodeId === node.id;

              return (
                <g 
                  key={node.id} 
                  className={`graph-node-group ${isCenter ? 'center-node' : ''}`}
                  transform={`translate(${node.x}, ${node.y})`}
                  onMouseEnter={() => setHoveredNode(node)}
                  onMouseLeave={() => setHoveredNode(null)}
                  onPointerDown={(e) => handlePointerDown(e, node.id)}
                  onClick={() => setSelectedNode(node)}
                  style={{ cursor: isDragging ? 'grabbing' : 'grab' }}
                >
                  {/* Glowing ambient ring */}
                  <circle
                    r={node.radius + (isHovered || isSelected ? 8 : 4)}
                    fill="none"
                    stroke={node.color}
                    strokeWidth={2}
                    strokeOpacity={isHovered || isSelected ? 0.8 : 0.25}
                    filter="url(#glow)"
                  />

                  {/* Secondary thin ring for design texture */}
                  <circle
                    r={node.radius + 3}
                    fill="none"
                    stroke={node.color}
                    strokeWidth={1}
                    strokeOpacity={0.4}
                  />

                  {/* Main Circle (fill gradient) */}
                  <circle
                    r={node.radius}
                    fill={getNodeFill(node)}
                    stroke={node.color}
                    strokeWidth={isHovered || isSelected ? 2.5 : 1.5}
                  />

                  {/* Icon */}
                  <foreignObject 
                    x={-10} 
                    y={-10} 
                    width={20} 
                    height={20} 
                    style={{ pointerEvents: 'none' }}
                  >
                    <Icon size={20} style={{ color: '#ffffff' }} />
                  </foreignObject>

                  {/* Text Label */}
                  <text
                    y={node.radius + 15}
                    textAnchor="middle"
                    fill={isHovered || isSelected ? '#ffffff' : '#8a99ad'}
                    fontSize={11}
                    fontWeight={isHovered || isSelected ? '600' : '400'}
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
                <p><strong>Coordinates:</strong> X: {selectedNode.x.toFixed(0)}, Y: {selectedNode.y.toFixed(0)}</p>
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
              <Network size={32} className="network-icon text-cyan" />
              <p>Hover or click on any node in the topology map to inspect metadata links and network relations. Drag nodes to customize placement.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
