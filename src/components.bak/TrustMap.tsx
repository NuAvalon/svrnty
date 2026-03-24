// src/components/TrustMap.tsx
// Constellation-style trust graph visualization using Canvas API.
// Binary trust: known (outer ring) or trusted (inner ring).
// Decayed trust fades — stars dim and drift outward.

"use client";

import React, { useRef, useEffect, useState, useCallback } from 'react';
import { isDecayed, daysUntilDecay } from '@/lib/trust/types';
import type { TrustEdge } from '@/lib/trust/types';

interface TrustMapProps {
  ownerFingerprint: string;
  ownerName: string;
  contacts: TrustEdge[];
}

interface Node {
  id: string;
  name: string;
  trusted: boolean;
  decayed: boolean;
  daysLeft: number;
  x: number;
  y: number;
  isOwner: boolean;
}

const COLORS = {
  trusted: '#c8a84e',    // gold — inside the walls
  known: '#5a7a9a',      // cool blue — outside
  decayed: '#4a3a2a',    // faded amber — trust expired
  owner: '#c8a84e',      // gold
  bg: '#0a0a0f',
};

const RADIUS = {
  trusted: 130,   // inner ring
  known: 280,     // outer ring
  decayed: 340,   // drifted out
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
      trusted: true,
      decayed: false,
      daysLeft: Infinity,
      x: cx,
      y: cy,
      isOwner: true,
    };

    // Group contacts by state for even distribution
    const trustedContacts = contacts.filter(c => c.trusted && !isDecayed(c));
    const knownContacts = contacts.filter(c => !c.trusted);
    const decayedContacts = contacts.filter(c => c.trusted && isDecayed(c));

    const placeInRing = (items: TrustEdge[], radius: number, trusted: boolean, decayed: boolean): Node[] => {
      return items.map((c, i) => {
        const angleStep = (2 * Math.PI) / Math.max(items.length, 1);
        const angle = angleStep * i + (Math.random() - 0.5) * 0.3;
        const r = radius + (Math.random() - 0.5) * 40;

        return {
          id: c.peer_fingerprint,
          name: c.peer_name,
          trusted,
          decayed,
          daysLeft: trusted ? daysUntilDecay(c) : 0,
          x: cx + Math.cos(angle) * r,
          y: cy + Math.sin(angle) * r,
          isOwner: false,
        };
      });
    };

    nodesRef.current = [
      owner,
      ...placeInRing(trustedContacts, RADIUS.trusted, true, false),
      ...placeInRing(decayedContacts, RADIUS.decayed, true, true),
      ...placeInRing(knownContacts, RADIUS.known, false, false),
    ];
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
      ctx.fillStyle = COLORS.bg;
      ctx.fillRect(0, 0, width, height);

      const nodes = nodesRef.current;
      if (nodes.length === 0) return;

      const owner = nodes[0];

      // Draw the two walls
      // Inner wall — trusted
      ctx.beginPath();
      ctx.arc(cx, cy, RADIUS.trusted + 30, 0, Math.PI * 2);
      ctx.strokeStyle = `${COLORS.trusted}25`;
      ctx.lineWidth = 1;
      ctx.stroke();

      ctx.fillStyle = `${COLORS.trusted}30`;
      ctx.font = '9px monospace';
      ctx.textAlign = 'left';
      ctx.fillText('trusted', cx + RADIUS.trusted + 36, cy - 4);

      // Outer wall — known
      ctx.beginPath();
      ctx.arc(cx, cy, RADIUS.known + 30, 0, Math.PI * 2);
      ctx.strokeStyle = `${COLORS.known}20`;
      ctx.lineWidth = 1;
      ctx.stroke();

      ctx.fillStyle = `${COLORS.known}30`;
      ctx.fillText('known', cx + RADIUS.known + 36, cy - 4);

      // Draw edges (connections to owner)
      for (let i = 1; i < nodes.length; i++) {
        const node = nodes[i];
        const color = node.decayed ? COLORS.decayed : node.trusted ? COLORS.trusted : COLORS.known;
        const alpha = node.decayed ? 0.06 : node.trusted ? 0.2 : 0.08;

        ctx.beginPath();
        ctx.moveTo(owner.x, owner.y);
        ctx.lineTo(node.x, node.y);
        ctx.strokeStyle = color + Math.round(alpha * 255).toString(16).padStart(2, '0');
        ctx.lineWidth = node.trusted && !node.decayed ? 1 : 0.5;
        ctx.stroke();
      }

      // Draw nodes
      for (const node of nodes) {
        const floatX = Math.sin(time * 2 + node.x * 0.01) * 1.5;
        const floatY = Math.cos(time * 1.5 + node.y * 0.01) * 1.5;
        const drawX = node.x + floatX;
        const drawY = node.y + floatY;

        if (node.isOwner) {
          // Owner node — gold star
          const pulse = 1 + Math.sin(time * 3) * 0.1;

          const gradient = ctx.createRadialGradient(drawX, drawY, 0, drawX, drawY, 30 * pulse);
          gradient.addColorStop(0, 'rgba(200, 168, 78, 0.3)');
          gradient.addColorStop(1, 'rgba(200, 168, 78, 0)');
          ctx.fillStyle = gradient;
          ctx.fillRect(drawX - 30, drawY - 30, 60, 60);

          ctx.beginPath();
          ctx.arc(drawX, drawY, 8, 0, Math.PI * 2);
          ctx.fillStyle = COLORS.owner;
          ctx.fill();

          ctx.fillStyle = COLORS.owner;
          ctx.font = 'bold 11px monospace';
          ctx.textAlign = 'center';
          ctx.fillText(node.name, drawX, drawY + 22);
          ctx.font = '9px monospace';
          ctx.fillStyle = '#8a8070';
          ctx.fillText('you', drawX, drawY + 34);
        } else {
          const color = node.decayed ? COLORS.decayed : node.trusted ? COLORS.trusted : COLORS.known;
          const isHovered = hoveredNode?.id === node.id;
          const radius = isHovered ? 7 : node.trusted ? 5 : 4;

          // Glow for trusted
          if (node.trusted && !node.decayed) {
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
          ctx.globalAlpha = node.decayed ? 0.5 : 1;
          ctx.fill();
          ctx.globalAlpha = 1;

          // Label
          ctx.fillStyle = isHovered ? '#e0dcd0' : color + (node.decayed ? '80' : 'aa');
          ctx.font = `${isHovered ? '11px' : '10px'} monospace`;
          ctx.textAlign = 'center';
          ctx.fillText(node.name, drawX, drawY + radius + 14);

          if (isHovered) {
            ctx.fillStyle = '#8a8070';
            ctx.font = '9px monospace';
            const status = node.decayed ? 'decayed' : node.trusted ? 'trusted' : 'known';
            ctx.fillText(status, drawX, drawY + radius + 26);
            ctx.fillText(node.id.slice(0, 16) + '...', drawX, drawY + radius + 38);
            if (node.trusted && !node.decayed) {
              const decayText = node.daysLeft > 365
                ? `${Math.round(node.daysLeft / 365)}y until decay`
                : `${node.daysLeft}d until decay`;
              ctx.fillStyle = node.daysLeft < 90 ? '#d47a7a' : '#6a8a5a';
              ctx.fillText(decayText, drawX, drawY + radius + 50);
            }
          }
        }
      }

      // Legend
      ctx.textAlign = 'left';
      let ly = 24;
      ctx.fillStyle = '#5a5548';
      ctx.font = '9px monospace';
      ctx.fillText('TRUST MAP', 16, ly);
      ly += 20;

      // Trusted
      ctx.beginPath();
      ctx.arc(24, ly - 3, 4, 0, Math.PI * 2);
      ctx.fillStyle = COLORS.trusted;
      ctx.fill();
      ctx.fillStyle = COLORS.trusted + 'cc';
      ctx.font = '9px monospace';
      ctx.fillText('trusted', 34, ly);
      ly += 16;

      // Known
      ctx.beginPath();
      ctx.arc(24, ly - 3, 4, 0, Math.PI * 2);
      ctx.fillStyle = COLORS.known;
      ctx.fill();
      ctx.fillStyle = COLORS.known + 'cc';
      ctx.fillText('known', 34, ly);
      ly += 16;

      // Decayed
      ctx.beginPath();
      ctx.arc(24, ly - 3, 4, 0, Math.PI * 2);
      ctx.fillStyle = COLORS.decayed;
      ctx.fill();
      ctx.fillStyle = COLORS.decayed + 'cc';
      ctx.fillText('decayed', 34, ly);

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
    let closestDist = 30;

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
        background: COLORS.bg,
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
