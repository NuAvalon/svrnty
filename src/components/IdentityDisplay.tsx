// src/components/IdentityDisplay.tsx
"use client";

import React from 'react';

interface IdentityDisplayProps {
  identity: any;
  onSwitchIdentity: () => void;
  showDebug?: boolean;
  onShowDebug?: () => void;
}

export function IdentityDisplay({ 
  identity, 
  onSwitchIdentity, 
  showDebug = false, 
  onShowDebug 
}: IdentityDisplayProps) {
  if (!identity) return null;

  // Helper function to safely extract identity data
  const getIdentityData = (identity: any) => {
    // Log the identity structure for debugging
    console.log('IdentityDisplay received:', identity);
    
    // Try different possible structures
    const structures = [
      // Structure 1: { identity: { identity: { name, fingerprint } }, fingerprint }
      identity?.identity?.identity ? {
        name: identity.identity.identity.name,
        fingerprint: identity.fingerprint || identity.identity.identity.fingerprint,
        email: identity.identity.identity.email
      } : null,
      // Structure 2: { identity: { name, fingerprint }, fingerprint }
      identity?.identity ? {
        name: identity.identity.name,
        fingerprint: identity.fingerprint || identity.identity.fingerprint,
        email: identity.identity.email
      } : null,
      // Structure 3: Direct object { name, fingerprint }
      identity?.name ? {
        name: identity.name,
        fingerprint: identity.fingerprint,
        email: identity.email
      } : null
    ];

    // Find the first structure that has both name and fingerprint
    for (const struct of structures) {
      if (struct?.name && struct?.fingerprint) {
        console.log('Using identity structure:', struct);
        return struct;
      }
    }

    // Fallback: extract what we can
    const name = identity?.identity?.identity?.name || 
                 identity?.identity?.name || 
                 identity?.name || 
                 'Unknown';
    
    const fingerprint = identity?.fingerprint ||
                       identity?.identity?.fingerprint ||
                       identity?.identity?.identity?.fingerprint ||
                       'N/A';
    
    const email = identity?.identity?.identity?.email ||
                  identity?.identity?.email ||
                  identity?.email ||
                  'No email';

    const result = { name, fingerprint, email };
    console.log('Using fallback identity structure:', result);
    return result;
  };

  const { name, fingerprint, email } = getIdentityData(identity);

  return (
    <div className="mt-4 flex items-center justify-center gap-4">
      <div className="text-sm text-muted-foreground">
        <div className="flex items-center gap-2">
          <span>Active Identity:</span>
          <span className="font-medium text-foreground">{name}</span>
          <span className="font-mono text-xs">
            ({fingerprint.slice(0, 8)}...)
          </span>
        </div>
        <div className="text-xs text-center mt-1">
          {email}
        </div>
      </div>
      
      <div className="flex gap-2">
        <button
          onClick={onSwitchIdentity}
          className="text-xs text-blue-600 hover:text-blue-700 underline"
        >
          Switch Identity
        </button>
        
        {showDebug && onShowDebug && (
          <button
            onClick={onShowDebug}
            className="text-xs text-slate-500 hover:text-slate-700 underline"
          >
            Debug
          </button>
        )}
      </div>
    </div>
  );
}