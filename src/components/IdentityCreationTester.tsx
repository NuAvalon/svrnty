"use client";

import React, { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { 
  RefreshCw, CheckCircle, AlertTriangle, User, 
  Mail, Key, FileText, Folder, Plus
} from 'lucide-react';

export function IdentityCreationTester() {
  const [loading, setLoading] = useState(false);
  const [name, setName] = useState('Test User');
  const [email, setEmail] = useState('test@example.com');
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [step, setStep] = useState<'form' | 'creating' | 'success' | 'error'>('form');

  const createIdentity = async () => {
    if (!name.trim() || !email.trim()) {
      setError('Name and email are required');
      return;
    }

    setLoading(true);
    setError(null);
    setStep('creating');
    setResult(null);

    try {
      console.log('🚀 Creating identity...');
      console.log('📝 Name:', name);
      console.log('📧 Email:', email);

      const response = await fetch('/api/identity', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name: name.trim(), email: email.trim() }),
      });

      console.log('📡 Response status:', response.status);
      console.log('📡 Response headers:', Object.fromEntries(response.headers.entries()));

      const data = await response.json();
      console.log('📦 Response data:', data);

      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}: ${data.details || 'Unknown error'}`);
      }

      setResult(data);
      setStep('success');
      console.log('✅ Identity created successfully!');
      console.log('🆔 Fingerprint:', data.fingerprint);

    } catch (err) {
      console.error('❌ Identity creation failed:', err);
      setError(err instanceof Error ? err.message : 'Unknown error occurred');
      setStep('error');
    } finally {
      setLoading(false);
    }
  };

  const testDirectStorage = async () => {
    try {
      console.log('🧪 Testing direct storage...');
      
      // Test if we can check storage directory
      const response = await fetch('/api/debug/diagnose');
      const data = await response.json();
      
      console.log('📁 Storage info:', data);
      
      if (!data.directoryExists) {
        setError('Storage directory does not exist');
      } else {
        console.log('✅ Storage directory exists');
        console.log('📊 Files:', {
          identities: data.identityFiles,
          keys: data.keyFiles,
          contacts: data.contactFiles
        });
      }
      
    } catch (err) {
      console.error('❌ Storage test failed:', err);
      setError(`Storage test failed: ${err}`);
    }
  };

  const reset = () => {
    setResult(null);
    setError(null);
    setStep('form');
  };

  return (
    <Card className="w-full max-w-2xl mx-auto">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Plus className="h-5 w-5" />
          Identity Creation Tester
        </CardTitle>
      </CardHeader>
      
      <CardContent className="space-y-4">
        {/* Current Status */}
        <div className="flex items-center gap-2 mb-4">
          <Badge variant={step === 'form' ? 'default' : 'outline'}>
            1. Form
          </Badge>
          <Badge variant={step === 'creating' ? 'default' : 'outline'}>
            2. Creating
          </Badge>
          <Badge variant={step === 'success' ? 'default' : step === 'error' ? 'destructive' : 'outline'}>
            3. Result
          </Badge>
        </div>

        {/* Error Display */}
        {error && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Creation Failed</AlertTitle>
            <AlertDescription className="whitespace-pre-wrap">{error}</AlertDescription>
          </Alert>
        )}

        {/* Success Display */}
        {result && step === 'success' && (
          <Alert className="border-green-200 bg-green-50">
            <CheckCircle className="h-4 w-4 text-green-600" />
            <AlertTitle>Identity Created Successfully!</AlertTitle>
            <AlertDescription>
              <div className="mt-2 space-y-2">
                <div><strong>Name:</strong> {result.identity?.identity?.name}</div>
                <div><strong>Email:</strong> {result.identity?.identity?.email}</div>
                <div><strong>Fingerprint:</strong> 
                  <code className="bg-green-100 px-1 rounded text-xs ml-1">
                    {result.fingerprint}
                  </code>
                </div>
                <div><strong>Verification Status:</strong> {result.identity?.verification?.status}</div>
              </div>
            </AlertDescription>
          </Alert>
        )}

        {/* Form */}
        {step === 'form' && (
          <div className="space-y-4">
            <div className="grid w-full items-center gap-1.5">
              <label htmlFor="name" className="text-sm font-medium flex items-center gap-2">
                <User className="h-4 w-4" />
                Name
              </label>
              <Input
                id="name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Enter your name"
              />
            </div>
            
            <div className="grid w-full items-center gap-1.5">
              <label htmlFor="email" className="text-sm font-medium flex items-center gap-2">
                <Mail className="h-4 w-4" />
                Email
              </label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter your email"
              />
            </div>

            <div className="flex gap-3">
              <Button 
                onClick={createIdentity}
                disabled={loading || !name.trim() || !email.trim()}
                className="flex-1"
              >
                {loading ? (
                  <>
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    Creating Identity...
                  </>
                ) : (
                  <>
                    <Key className="h-4 w-4 mr-2" />
                    Create Identity
                  </>
                )}
              </Button>
              
              <Button 
                onClick={testDirectStorage}
                variant="outline"
              >
                <Folder className="h-4 w-4 mr-2" />
                Test Storage
              </Button>
            </div>
          </div>
        )}

        {/* Creating State */}
        {step === 'creating' && (
          <div className="text-center py-8">
            <RefreshCw className="h-12 w-12 animate-spin mx-auto mb-4 text-blue-600" />
            <p className="text-lg font-medium">Creating your identity...</p>
            <p className="text-sm text-gray-600">This may take a few seconds</p>
          </div>
        )}

        {/* Action Buttons for Results */}
        {(step === 'success' || step === 'error') && (
          <div className="flex gap-3 pt-4">
            <Button 
              onClick={reset}
              variant="outline"
              className="flex-1"
            >
              Create Another
            </Button>
            
            <Button 
              onClick={testDirectStorage}
              variant="outline"
            >
              <Folder className="h-4 w-4 mr-2" />
              Check Storage
            </Button>
            
            {step === 'success' && (
              <Button 
                onClick={() => window.location.reload()}
                className="flex-1 bg-green-600 hover:bg-green-700"
              >
                Use This Identity
              </Button>
            )}
          </div>
        )}

        {/* Debug Info */}
        <div className="text-xs text-gray-500 border-t pt-4">
          <p><strong>Debug Info:</strong></p>
          <p>• API endpoint: POST /api/identity</p>
          <p>• Storage: ~/.soverentity/</p>
          <p>• Check browser console for detailed logs</p>
        </div>
      </CardContent>
    </Card>
  );
}