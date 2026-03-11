// app/page.tsx
"use client";

import { useState, useEffect, useCallback } from 'react';
import { SoverentityFrontend } from '@/components/SoverentityFrontend';
import { ContactManagement } from '@/components/ContactManagement';
import { SignalComposer, SignalReceiver, SignalLink } from '@/components/SignalSender';
import { TrustMap } from '@/components/TrustMap';
import { HelpGuide } from '@/components/HelpGuide';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import type { SignedSignal, TrustSignal, TrustEdge } from '@/lib/trust/types';

export default function Home() {
  const [identity, setIdentity] = useState<any>(null);
  const [contacts, setContacts] = useState<TrustEdge[]>([]);
  const [contactsForSignals, setContactsForSignals] = useState<Array<{ fingerprint: string; name: string; trusted: boolean; signalHandle?: string }>>([]);

  const handleIdentityUpdate = (newIdentity: any) => {
    setIdentity(newIdentity);
  };

  // Load contacts when identity is available
  useEffect(() => {
    if (!identity?.identity?.fingerprint) return;

    const loadContacts = async () => {
      try {
        const res = await fetch(`/api/contacts?fingerprint=${identity.identity.fingerprint}`);
        if (res.ok) {
          const data = await res.json();
          const rawContacts = data.contacts || [];

          // Map to TrustEdge format for TrustMap
          const edges: TrustEdge[] = rawContacts.map((c: any) => ({
            id: c.id,
            peer_fingerprint: c.peer_fingerprint || c.fingerprint || c.id,
            peer_name: c.peer_name || c.name,
            peer_email: c.peer_email || c.email || '',
            peer_public_key: c.peer_public_key || c.public_key || '',
            trusted: c.trusted ?? (c.trust_level === 'verified' || c.trust_level === 'trusted'),
            trusted_since: c.trusted_since || c.verified_at || null,
            last_interaction: c.last_interaction || c.verified_at || c.added_at || new Date().toISOString(),
            decay_days: c.decay_days || 730,
            trust_history: c.trust_history || [],
            verification: c.verification || { method: 'none', verified_at: null },
            mutual: c.mutual || { they_trust_me: null, last_sync: null, reciprocal: false },
            tags: c.tags || c.metadata?.tags || [],
            notes: c.notes || c.metadata?.notes || '',
            connection_channels: c.connection_channels || [],
            added_at: c.added_at || new Date().toISOString(),
          }));

          setContacts(edges);

          // Simplified list for signal composer
          setContactsForSignals(edges.map(e => ({
            fingerprint: e.peer_fingerprint,
            name: e.peer_name,
            trusted: e.trusted,
            signalHandle: e.connection_channels?.includes('signal') ? e.peer_name : undefined,
          })));
        }
      } catch (err) {
        console.error('Failed to load contacts:', err);
      }
    };

    loadContacts();
  }, [identity]);

  // Real signal signing — calls server-side API (private keys never leave server)
  const handleSendSignal = useCallback(async (payload: TrustSignal, recipientFingerprint: string): Promise<SignedSignal> => {
    const fingerprint = identity?.identity?.fingerprint;
    if (!fingerprint) {
      throw new Error('No identity loaded — create or load your identity first');
    }

    const res = await fetch('/api/signals/sign', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint, payload, recipientFingerprint }),
    });

    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || 'Failed to sign signal');
    }

    return data.signal;
  }, [identity]);

  // Real signal verification — calls server-side API
  const handleReceiveSignal = useCallback(async (signal: SignedSignal) => {
    const res = await fetch('/api/signals/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ signal, senderFingerprint: signal.from }),
    });

    const data = await res.json();
    return {
      valid: data.valid,
      senderName: data.senderName || signal.from.slice(0, 16) + '...',
    };
  }, []);

  return (
    <div className="min-h-screen p-8" style={{ background: '#0a0a0f', color: '#e0dcd0' }}>
      <header className="mb-12 text-center relative">
        <h1 className="text-3xl font-bold mb-2" style={{ color: '#c8a84e', letterSpacing: '3px' }}>SVRNTY</h1>
        <p style={{ color: '#8a8070', fontSize: '14px' }}>Self-Sovereign Trust Network</p>
        <p style={{ color: '#5a5548', fontSize: '11px', marginTop: '4px' }}>from NuAvalon</p>
        <HelpGuide />
      </header>

      <main className="max-w-6xl mx-auto">
        {!identity ? (
          <SoverentityFrontend onIdentityUpdate={handleIdentityUpdate} />
        ) : (
          <Tabs defaultValue="trust-map" className="w-full">
            <TabsList className="w-full max-w-2xl mx-auto mb-8">
              <TabsTrigger value="trust-map" className="flex-1">Trust Map</TabsTrigger>
              <TabsTrigger value="signals" className="flex-1">Signals</TabsTrigger>
              <TabsTrigger value="contacts" className="flex-1">Contacts</TabsTrigger>
              <TabsTrigger value="identity" className="flex-1">Identity</TabsTrigger>
            </TabsList>

            <TabsContent value="trust-map">
              <TrustMap
                ownerFingerprint={identity.identity.fingerprint}
                ownerName={identity.identity.name}
                contacts={contacts}
              />
            </TabsContent>

            <TabsContent value="signals">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-4xl mx-auto">
                <SignalComposer
                  myFingerprint={identity.identity.fingerprint}
                  contacts={contactsForSignals}
                  onSend={handleSendSignal}
                />
                <SignalReceiver onReceive={handleReceiveSignal} />
              </div>
            </TabsContent>

            <TabsContent value="contacts">
              <ContactManagement identity={identity} />
            </TabsContent>

            <TabsContent value="identity">
              <SoverentityFrontend
                existingIdentity={identity}
                onIdentityUpdate={handleIdentityUpdate}
              />
            </TabsContent>
          </Tabs>
        )}
      </main>

      <footer className="mt-16 text-center text-sm" style={{ color: '#5a5548' }}>
        <p>SVRNTY — Self-Sovereign Trust Network</p>
        <p className="mt-1">All data is encrypted and stored locally. No servers. No tracking.</p>
      </footer>
    </div>
  );
}
