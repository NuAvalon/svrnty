// src/components/SimpleQRCode.tsx
"use client";

import React from 'react';

// A simple SVG-based QR Code component
// This is for demonstration purposes only
// It doesn't actually generate a real QR code, but gives the appearance of one

export function SimpleQRCode({ value }: { value: string }) {
  const size = 256;
  const squareSize = 8; // Size of each "module" (square)
  const borderSize = 4 * squareSize; // Quiet zone
  const actualSize = size - 2 * borderSize;
  
  // Generate a deterministic but random-looking pattern based on the value
  const generatePattern = (value: string) => {
    // Basic hash function to generate a 32-bit number from a string
    const hash = (str: string) => {
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash |= 0; // Convert to 32bit integer
      }
      return hash;
    };
    
    // Generate a pattern
    const pattern = [];
    const rows = Math.floor(actualSize / squareSize);
    const cols = Math.floor(actualSize / squareSize);
    
    // Always have finder patterns (the three large squares in corners)
    const finderPattern = [
      // Top-left
      { x: 0, y: 0, width: 7, height: 7 },
      // Top-right
      { x: cols - 7, y: 0, width: 7, height: 7 },
      // Bottom-left
      { x: 0, y: rows - 7, width: 7, height: 7 },
    ];
    
    // Add finder pattern outlines
    finderPattern.forEach(fp => {
      for (let r = fp.y; r < fp.y + fp.height; r++) {
        for (let c = fp.x; c < fp.x + fp.width; c++) {
          if (r === fp.y || r === fp.y + fp.height - 1 || c === fp.x || c === fp.x + fp.width - 1 ||
              (r >= fp.y + 2 && r <= fp.y + fp.height - 3 && c >= fp.x + 2 && c <= fp.x + fp.width - 3)) {
            pattern.push({ row: r, col: c });
          }
        }
      }
    });
    
    // Add data-like pattern
    let seedValue = hash(value);
    for (let i = 0; i < cols * rows / 4; i++) {
      // Generate next pseudo-random number
      seedValue = (seedValue * 1664525 + 1013904223) % 4294967296;
      const row = Math.floor(seedValue / (4294967296 / rows));
      const col = Math.floor((seedValue % 4294967296) / (4294967296 / cols));
      
      // Check if this position is already in a finder pattern
      const inFinderPattern = finderPattern.some(fp => 
        row >= fp.y && row < fp.y + fp.height && 
        col >= fp.x && col < fp.x + fp.width
      );
      
      if (!inFinderPattern) {
        pattern.push({ row, col });
      }
    }
    
    return pattern;
  };
  
  const pattern = generatePattern(value);
  
  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      style={{ background: 'white' }}
    >
      {/* Add QR code pattern */}
      {pattern.map((p, index) => (
        <rect
          key={index}
          x={borderSize + p.col * squareSize}
          y={borderSize + p.row * squareSize}
          width={squareSize}
          height={squareSize}
          fill="black"
        />
      ))}
    </svg>
  );
}