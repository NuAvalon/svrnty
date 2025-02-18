"use client";

import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Shield, Key, UserCheck, Lock, Mail } from 'lucide-react';

interface VerificationState {
  loading: boolean;
  error: string | null;
  status: 'unverified' | 'verification_sent' | 'verified';
  challenge?: string;
}

interface Identity {
  identity: {
    name: string;
    email: string;
    fingerprint: string;
    public_key: string;
  };
  verification: {
    status: 'unverified' | 'verified';
    method: string | null;
    verified_at: string | null;
    proof?: string;
  };
  claims?: IdentityClaim[];
}

export function SoverentityFrontend() {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    email: '',
  });

  const [verificationState, setVerificationState] = useState<VerificationState>({
    loading: false,
    error: null,
    status: 'unverified'
  });

  useEffect(() => {
    console.log('Identity state changed:', identity);
  }, [identity]);

  useEffect(() => {
    // Load saved identity on mount
    const savedIdentity = localStorage.getItem('soverentity-identity');
    if (savedIdentity) {
      try {
        const parsed = JSON.parse(savedIdentity);
        setIdentity(parsed);
        console.log('Loaded saved identity:', parsed);
      } catch (e) {
        console.error('Failed to load saved identity:', e);
      }
    }
  }, []);

  const [verificationCode, setVerificationCode] = useState('');

  const handleCreateIdentity = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('/api/identity', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      const data = await response.json();
      console.log('Create identity response:', data);

      if (!response.ok) {
        throw new Error(data.error || 'Failed to create identity');
      }

      if (!data.identity) {
        throw new Error('No identity data received');
      }

      setIdentity(data.identity);
      localStorage.setItem('soverentity-identity', JSON.stringify(data.identity));
      console.log('Saved identity:', data.identity);
    } catch (err) {
      console.error('Error creating identity:', err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleVerification = async () => {
    try {
      setVerificationState(prev => ({ ...prev, loading: true, error: null }));

      if (!identity?.identity?.fingerprint || !identity?.identity?.email) {
        throw new Error('Invalid identity data');
      }

      const payload = {
        fingerprint: identity.identity.fingerprint,
        type: 'email',
        value: identity.identity.email
      };
      console.log('Sending verification payload:', payload);

      const response = await fetch('/api/identity/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload)
      });

      const text = await response.text();
      console.log('Raw response:', text);

      const data = JSON.parse(text);
      console.log('Parsed response data:', data);

      if (!response.ok) {
        throw new Error(data.error || 'Verification failed');
      }

      setVerificationState(prev => ({ 
        ...prev, 
        status: 'verification_sent',
        challenge: data.challenge,
        loading: false 
      }));
    } catch (err) {
      console.error('Verification error:', err);
      setVerificationState(prev => ({ 
        ...prev, 
        error: err instanceof Error ? err.message : 'Verification failed',
        loading: false 
      }));
    }
  };

  const handleVerifyCode = async () => {
    try {
      setVerificationState(prev => ({ ...prev, loading: true, error: null }));

      const response = await fetch('/api/identity/verify', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fingerprint: identity.identity.fingerprint,
          code: verificationCode,
          challenge: verificationState.challenge
        })
      });

      const data = await response.json();
      console.log('Verification response:', data);

      if (!response.ok) {
        throw new Error(data.error || 'Code verification failed');
      }

      setVerificationState(prev => ({ 
        ...prev, 
        status: 'verified',
        loading: false 
      }));

      if (data.identity) {
        setIdentity(data.identity);
        localStorage.setItem('soverentity-identity', JSON.stringify(data.identity));
      }
    } catch (err) {
      setVerificationState(prev => ({ 
        ...prev, 
        error: err instanceof Error ? err.message : 'Code verification failed',
        loading: false 
      }));
    }
  };

  return (
    <Card className="w-full max-w-2xl mx-auto">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-6 w-6" />
          Soverentity Identity
        </CardTitle>
      </CardHeader>
      <CardContent>
        {error && (
          <Alert variant="destructive" className="mb-4">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {!identity ? (
          <div className="space-y-4">
            <Input
              placeholder="Name"
              value={formData.name}
              onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
            />

            <Input
              type="email"
              placeholder="Email address"
              value={formData.email}
              onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
            />

            <Button 
              onClick={handleCreateIdentity}
              className="w-full"
              disabled={loading || !formData.name || !formData.email}
            >
              {loading ? 'Creating...' : 'Create Sovereign Identity'}
            </Button>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="p-4 bg-gray-50 rounded-lg space-y-2">
              <div className="flex items-center gap-2">
                <Key className="h-5 w-5" />
                <span className="font-medium">Identity Created</span>
              </div>
              
              <div className="text-sm text-gray-600">
                Fingerprint: {identity.identity.fingerprint?.slice(0, 16)}...
              </div>

              <div className="flex items-center gap-2 text-sm">
                <Lock className={identity.verification?.status === 'verified' ? 'text-green-500' : 'text-yellow-500'} />
                Status: {identity.verification?.status || 'unverified'}
              </div>
            </div>

            {identity.verification?.status !== 'verified' && (
              <div className="mt-4 space-y-4">
                {verificationState.status === 'verification_sent' ? (
                  <div className="space-y-4">
                    <Input
                      placeholder="Enter verification code"
                      value={verificationCode}
                      onChange={(e) => setVerificationCode(e.target.value)}
                      maxLength={6}
                    />
                    <Button
                      onClick={handleVerifyCode}
                      disabled={verificationState.loading || !verificationCode}
                      className="w-full"
                    >
                      {verificationState.loading ? 'Verifying...' : 'Submit Code'}
                    </Button>
                  </div>
                ) : (
                  <Button
                    onClick={handleVerification}
                    disabled={verificationState.loading}
                    className="w-full"
                  >
                    {verificationState.loading ? 'Sending Code...' : 'Verify Email'}
                  </Button>
                )}
                {verificationState.error && (
                  <Alert variant="destructive">
                    <AlertDescription>{verificationState.error}</AlertDescription>
                  </Alert>
                )}
              </div>
            )}

            {identity.verification?.status === 'verified' && (
              <Alert className="mt-4">
                <AlertDescription>
                  Identity verified successfully!
                </AlertDescription>
              </Alert>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}