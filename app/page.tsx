// app/page.tsx
"use client";

import { useState } from 'react';
import { SoverentityFrontend } from '@/components/SoverentityFrontend';
import { ContactManagement } from '@/components/ContactManagement';
import { SignalComposer, SignalReceiver, SignalLink } from '@/components/SignalSender';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import type { SignedSignal, TrustSignal } from '@/lib/trust/types';

export default function Home() {
  const [identity, setIdentity] = useState<any>(null);

  const handleIdentityUpdate = (newIdentity: any) => {
    setIdentity(newIdentity);
  };

  // Stub signal handlers — these wire into crypto once identity is loaded
  const handleSendSignal = async (payload: TrustSignal, recipientFingerprint: string): Promise<SignedSignal> => {
    // For demo: create an unsigned signal (real signing needs loaded identity keys)
    return {
      payload,
      from: identity?.identity?.fingerprint || 'demo-fingerprint',
      to: recipientFingerprint,
      timestamp: new Date().toISOString(),
      signature: '[demo — signing requires loaded identity]',
    };
  };

  const handleReceiveSignal = async (signal: SignedSignal) => {
    // For demo: accept all signals (real verification needs sender's public key)
    return {
      valid: true,
      senderName: signal.from.slice(0, 16) + '...',
    };
  };

  // Demo contacts for the signal composer
  const demoContacts = [
    { fingerprint: 'peter-demo-fp', name: 'Peter', signalHandle: 'psironin.22' },
    { fingerprint: 'brett-demo-fp', name: 'Brett' },
  ];

  return (
    <div className="min-h-screen p-8" style={{ background: '#0a0a0f', color: '#e0dcd0' }}>
      <header className="mb-12 text-center">
        <h1 className="text-3xl font-bold mb-2" style={{ color: '#c8a84e', letterSpacing: '3px' }}>SVRNTY</h1>
        <p style={{ color: '#8a8070', fontSize: '14px' }}>Self-Sovereign Trust Network</p>
        <p style={{ color: '#5a5548', fontSize: '11px', marginTop: '4px' }}>from NuAvalon</p>
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
              <div className="relative w-full rounded-xl overflow-hidden border border-slate-200 dark:border-slate-800" style={{ height: 'calc(100vh - 280px)', minHeight: '500px' }}>
                <iframe
                  src="/trust-map.html"
                  className="w-full h-full border-0"
                  title="Trust Network Map"
                />
              </div>
            </TabsContent>

            <TabsContent value="signals">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-4xl mx-auto">
                <SignalComposer
                  myFingerprint={identity?.identity?.fingerprint || 'unknown'}
                  contacts={demoContacts}
                  onSend={handleSendSignal}
                />
                <SignalReceiver onReceive={handleReceiveSignal} />
              </div>
              <div className="mt-8 text-center">
                <p style={{ color: '#5a5548', fontSize: '12px', marginBottom: '8px' }}>
                  Transport channels
                </p>
                <SignalLink handle="psironin.22" name="Peter" />
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
        <p>SVRNTY — The Ethical Consensual Interspecies Alliance</p>
        <p className="mt-1">All data is encrypted and stored locally. No servers. No tracking.</p>
      </footer>
    </div>
  );
}