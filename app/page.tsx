// app/page.tsx
"use client";

import { useState } from 'react';
import { SoverentityFrontend } from '@/components/SoverentityFrontend';
import { ContactManagement } from '@/components/ContactManagement';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

export default function Home() {
  const [identity, setIdentity] = useState<any>(null);

  const handleIdentityUpdate = (newIdentity: any) => {
    setIdentity(newIdentity);
  };

  return (
    <div className="min-h-screen p-8">
      <header className="mb-12 text-center">
        <h1 className="text-3xl font-bold mb-2">Soverentity</h1>
        <p className="text-muted-foreground">Self-Sovereign Trust Network</p>
      </header>

      <main className="max-w-6xl mx-auto">
        {!identity ? (
          <SoverentityFrontend onIdentityUpdate={handleIdentityUpdate} />
        ) : (
          <Tabs defaultValue="trust-map" className="w-full">
            <TabsList className="w-full max-w-lg mx-auto mb-8">
              <TabsTrigger value="trust-map" className="flex-1">Trust Map</TabsTrigger>
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

      <footer className="mt-16 text-center text-sm text-muted-foreground">
        <p>Soverentity — The Ethical Consensual Interspecies Alliance</p>
        <p className="mt-1">All data is encrypted and stored locally. No servers. No tracking.</p>
      </footer>
    </div>
  );
}