// src/components/TrustMap.tsx
// Constellation-style trust graph visualization using Canvas API.
// No external dependencies — pure React + Canvas.

"use client";

import React, { useRef, useEffect, useState, useCallback } from 'react';

interface TrustContact {
  fingerprint: string;
  name: string;
  trust_level?: number;
}

interface TrustMapProps {
  ownerFingerprint: string;
  ownerName: string;
  contacts: TrustContact[];
}

interface Node {
  id: string;
  name: string;
  level: number;
  x: number;
  y: number;
  vx: number;
  vy: number;
  isOwner: boolean;
}

const LEVEL_COLORS: Record<number, string> = {
  0: '#3a3a4a',  // stranger — dim
  1: '#5a7a9a',  // known — cool blue
  2: '#6a9a6a',  // verified — green
  3: '#c8a84e',  // trusted — gold
  4: '#d4785a',  // inner circle — warm amber
};

const LEVEL_LABELS: Record<number, string> = {
  0: 'stranger',
  1: 'known',
  2: 'verified',
  3: 'trusted',
  4: 'inner circle',
};

// Distance from center by trust level (closer = higher trust)
const LEVEL_RADIUS: Record<number, number> = {
  4: 80,
  3: 150,
  2: 220,
  1: 290,
  0: 360,
};

export function TrustMap({ ownerFingerprint, ownerName, contacts }: TrustMapProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const nodesRef = useRef<Node[]>([]);
  const animRef = useRef<number>(0);
  const [hoveredNode, setHoveredNode] = useState<Node | null>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  // Build nodes from contacts
  useEffect(() => {
    const cx = dimensions.width / 2;
    const cy = dimensions.height / 2;

    const owner: Node = {
      id: ownerFingerprint,
      name: ownerName,
      level: -1,
      x: cx,
      y: cy,
      vx: 0,
      vy: 0,
      isOwner: true,
    };

    const contactNodes: Node[] = contacts.map((c, i) => {
      const level = c.trust_level ?? 1;
      const radius = LEVEL_RADIUS[level] || 290;
      // Distribute evenly around the circle with slight randomness
      const angleStep = (2 * Math.PI) / Math.max(contacts.length, 1);
      const angle = angleStep * i + (Math.random() - 0.5) * 0.3;
      const r = radius + (Math.random() - 0.5) * 40;

      return {
        id: c.fingerprint,
        name: c.name,
        level,
        x: cx + Math.cos(angle) * r,
        y: cy + Math.sin(angle) * r,
        vx: 0,
        vy: 0,
        isOwner: false,
      };
    });

    nodesRef.current = [owner, ...contactNodes];
  }, [contacts, ownerFingerprint, ownerName, dimensions]);

  // Resize observer
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const observer = new ResizeObserver(entries => {
      for (const entry of entries) {
        setDimensions({
          width: entry.contentRect.width,
          height: entry.contentRect.height,
        });
      }
    });

    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  // Animation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let time = 0;

    const draw = () => {
      time += 0.005;
      const { width, height } = dimensions;
      const cx = width / 2;
      const cy = height / 2;
      const dpr = window.devicePixelRatio || 1;

      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.scale(dpr, dpr);

      // Clear
      ctx.fillStyle = '#0a0a0f';
      ctx.fillRect(0, 0, width, height);

      const nodes = nodesRef.current;
      if (nodes.length === 0) return;

      const owner = nodes[0];

      // Draw orbital rings
      for (const [level, radius] of Object.entries(LEVEL_RADIUS)) {
        const l = parseInt(level);
        ctx.beginPath();
        ctx.arc(cx, cy, radius, 0, Math.PI * 2);
        ctx.strokeStyle = `${LEVEL_COLORS[l]}20`;
        ctx.lineWidth = 1;
        ctx.stroke();

        // Level label on the ring
        ctx.fillStyle = `${LEVEL_COLORS[l]}40`;
        ctx.font = '9px monospace';
        ctx.fillText(LEVEL_LABELS[l], cx + radius + 8, cy - 4);
      }

      // Draw edges (connections to owner)
      for (let i = 1; i < nodes.length; i++) {
        const node = nodes[i];
        const color = LEVEL_COLORS[node.level] || LEVEL_COLORS[1];

        ctx.beginPath();
        ctx.moveTo(owner.x, owner.y);
        ctx.lineTo(node.x, node.y);

        // Edge opacity based on trust level
        const alpha = 0.08 + node.level * 0.07;
        ctx.strokeStyle = color + Math.round(alpha * 255).toString(16).padStart(2, '0');
        ctx.lineWidth = 0.5 + node.level * 0.3;
        ctx.stroke();
      }

      // Draw nodes
      for (const node of nodes) {
        // Gentle float animation
        const floatX = Math.sin(time * 2 + node.x * 0.01) * 1.5;
        const floatY = Math.cos(time * 1.5 + node.y * 0.01) * 1.5;
        const drawX = node.x + floatX;
        const drawY = node.y + floatY;

        if (node.isOwner) {
          // Owner node — gold star
          const pulse = 1 + Math.sin(time * 3) * 0.1;

          // Glow
          const gradient = ctx.createRadialGradient(drawX, drawY, 0, drawX, drawY, 30 * pulse);
          gradient.addColorStop(0, 'rgba(200, 168, 78, 0.3)');
          gradient.addColorStop(1, 'rgba(200, 168, 78, 0)');
          ctx.fillStyle = gradient;
          ctx.fillRect(drawX - 30, drawY - 30, 60, 60);

          // Core
          ctx.beginPath();
          ctx.arc(drawX, drawY, 8, 0, Math.PI * 2);
          ctx.fillStyle = '#c8a84e';
          ctx.fill();

          // Label
          ctx.fillStyle = '#c8a84e';
          ctx.font = 'bold 11px monospace';
          ctx.textAlign = 'center';
          ctx.fillText(node.name, drawX, drawY + 22);
          ctx.font = '9px monospace';
          ctx.fillStyle = '#8a8070';
          ctx.fillText('you', drawX, drawY + 34);
        } else {
          const color = LEVEL_COLORS[node.level] || LEVEL_COLORS[1];
          const isHovered = hoveredNode?.id === node.id;
          const radius = isHovered ? 7 : 4 + node.level * 0.5;

          // Glow for higher trust
          if (node.level >= 3) {
            const gradient = ctx.createRadialGradient(drawX, drawY, 0, drawX, drawY, 20);
            gradient.addColorStop(0, color + '30');
            gradient.addColorStop(1, color + '00');
            ctx.fillStyle = gradient;
            ctx.fillRect(drawX - 20, drawY - 20, 40, 40);
          }

          // Node dot
          ctx.beginPath();
          ctx.arc(drawX, drawY, radius, 0, Math.PI * 2);
          ctx.fillStyle = isHovered ? '#ffffff' : color;
          ctx.fill();

          // Label
          ctx.fillStyle = isHovered ? '#e0dcd0' : color + 'aa';
          ctx.font = `${isHovered ? '11px' : '10px'} monospace`;
          ctx.textAlign = 'center';
          ctx.fillText(node.name, drawX, drawY + radius + 14);

          if (isHovered) {
            ctx.fillStyle = '#8a8070';
            ctx.font = '9px monospace';
            ctx.fillText(`L${node.level} ${LEVEL_LABELS[node.level]}`, drawX, drawY + radius + 26);
            ctx.fillText(node.id.slice(0, 16) + '...', drawX, drawY + radius + 38);
          }
        }
      }

      // Legend
      ctx.textAlign = 'left';
      let ly = 24;
      ctx.fillStyle = '#5a5548';
      ctx.font = '9px monospace';
      ctx.fillText('TRUST LEVELS', 16, ly);
      ly += 16;

      for (let l = 4; l >= 1; l--) {
        ctx.beginPath();
        ctx.arc(24, ly - 3, 4, 0, Math.PI * 2);
        ctx.fillStyle = LEVEL_COLORS[l];
        ctx.fill();
        ctx.fillStyle = LEVEL_COLORS[l] + 'cc';
        ctx.font = '9px monospace';
        ctx.fillText(`L${l} ${LEVEL_LABELS[l]}`, 34, ly);
        ly += 16;
      }

      animRef.current = requestAnimationFrame(draw);
    };

    animRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(animRef.current);
  }, [dimensions, hoveredNode]);

  // Mouse interaction
  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    const nodes = nodesRef.current;
    let closest: Node | null = null;
    let closestDist = 30; // hover threshold

    for (const node of nodes) {
      if (node.isOwner) continue;
      const dx = node.x - mx;
      const dy = node.y - my;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < closestDist) {
        closest = node;
        closestDist = dist;
      }
    }

    setHoveredNode(closest);
  }, []);

  const isEmpty = contacts.length === 0;

  return (
    <div
      ref={containerRef}
      className="relative w-full rounded-xl overflow-hidden border"
      style={{
        height: 'calc(100vh - 280px)',
        minHeight: '500px',
        borderColor: 'rgba(180, 160, 100, 0.15)',
        background: '#0a0a0f',
      }}
    >
      <canvas
        ref={canvasRef}
        style={{ width: '100%', height: '100%', cursor: hoveredNode ? 'pointer' : 'default' }}
        onMouseMove={handleMouseMove}
        onMouseLeave={() => setHoveredNode(null)}
      />
      {isEmpty && (
        <div
          style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            textAlign: 'center',
            color: '#5a5548',
            fontFamily: "'SF Mono', 'Fira Code', monospace",
          }}
        >
          <div style={{ fontSize: '14px', marginBottom: '8px', color: '#8a8070' }}>
            Your constellation is empty
          </div>
          <div style={{ fontSize: '11px' }}>
            Add contacts to see your trust map come alive
          </div>
        </div>
      )}
    </div>
  );
}
