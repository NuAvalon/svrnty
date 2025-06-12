// app/page.tsx
"use client";

import { useState, useEffect } from 'react';
import { SoverentityFrontend } from '@/components/SoverentityFrontend';
import { ContactManagement } from '@/components/ContactManagement';
import { IdentitySelector } from '@/components/IdentitySelector';
import { IdentityDisplay } from '@/components/IdentityDisplay';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent } from '@/components/ui/card';
import { RefreshCw } from 'lucide-react';

export default function Home() {
  const [identity, setIdentity] = useState<any>(null);
  const [isClient, setIsClient] = useState(false);
  const [showIdentitySelector, setShowIdentitySelector] = useState(false);
  
  // Ensure we only render on the client side to avoid SSR issues
  useEffect(() => {
    setIsClient(true);
  }, []);

  // Function to handle identity selection from IdentitySelector
  const handleIdentitySelected = (selectedIdentity: any) => {
    console.log('🔍 Identity selected:', selectedIdentity);
    console.log('🔍 Identity structure:', JSON.stringify(selectedIdentity, null, 2));
    
    // Try to normalize the identity structure
    let normalizedIdentity = selectedIdentity;
    
    // If we got a result with both identity and fingerprint at top level
    if (selectedIdentity.identity && selectedIdentity.fingerprint) {
      normalizedIdentity = {
        identity: selectedIdentity.identity,
        fingerprint: selectedIdentity.fingerprint
      };
    }
    
    console.log('🔍 Normalized identity:', normalizedIdentity);
    setIdentity(normalizedIdentity);
    setShowIdentitySelector(false);
  };

  // Function to handle identity update from SoverentityFrontend
  const handleIdentityUpdate = (newIdentity: any) => {
    console.log('🔄 Identity updated:', newIdentity);
    console.log('🔄 Updated identity structure:', JSON.stringify(newIdentity, null, 2));
    setIdentity(newIdentity);
  };

  // Function to switch identities
  const handleSwitchIdentity = () => {
    setShowIdentitySelector(true);
  };

  // Show loading state during SSR
  if (!isClient) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Card className="w-full max-w-md">
          <CardContent className="p-8 text-center">
            <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-4 text-blue-600" />
            <p className="text-lg font-medium mb-2">Loading Soverentity</p>
            <p className="text-sm text-muted-foreground">
              Initializing decentralized identity system...
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Show identity selector if explicitly requested or no identity is loaded
  if (showIdentitySelector || !identity) {
    return (
      <div className="min-h-screen p-8">
        <header className="mb-12 text-center">
          <h1 className="text-3xl font-bold mb-2">Soverentity</h1>
          <p className="text-muted-foreground">Decentralized, Sovereign Contact Management</p>
        </header>

        <main className="max-w-6xl mx-auto">
          <IdentitySelector onIdentitySelected={handleIdentitySelected} />
        </main>

        <footer className="mt-16 text-center text-sm text-muted-foreground">
          <p>Soverentity - Self-Sovereign Identity & Contact Management</p>
          <p className="mt-1">All data is encrypted and stored locally in your browser.</p>
        </footer>
      </div>
    );
  }

  // Show main application with identity loaded
  return (
    <div className="min-h-screen p-8">
      <header className="mb-12 text-center">
        <h1 className="text-3xl font-bold mb-2">Soverentity</h1>
        <p className="text-muted-foreground">Decentralized, Sovereign Contact Management</p>
        
        <IdentityDisplay 
          identity={identity}
          onSwitchIdentity={handleSwitchIdentity}
        />
      </header>

      <main className="max-w-6xl mx-auto">
        <Tabs defaultValue="contacts" className="w-full">
          <TabsList className="w-full max-w-md mx-auto mb-8">
            <TabsTrigger value="identity" className="flex-1">Identity</TabsTrigger>
            <TabsTrigger value="contacts" className="flex-1">Contacts</TabsTrigger>
          </TabsList>
          
          <TabsContent value="identity">
            <SoverentityFrontend 
              existingIdentity={identity}
              onIdentityUpdate={handleIdentityUpdate}
            />
          </TabsContent>
          
          <TabsContent value="contacts">
            <ContactManagement identity={identity} />
          </TabsContent>
        </Tabs>
      </main>

      <footer className="mt-16 text-center text-sm text-muted-foreground">
        <p>Soverentity - Self-Sovereign Identity & Contact Management</p>
        <p className="mt-1">All data is encrypted and stored locally in your browser.</p>
      </footer>
    </div>
  );
}