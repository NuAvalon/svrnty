// src/components/SoverentityFrontend.tsx
"use client";

import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Shield, Key, UserCheck, Lock, Mail, CheckCircle2, Fingerprint, RefreshCw } from 'lucide-react';

interface SoverentityFrontendProps {
  existingIdentity?: any;
  onIdentityUpdate?: (identity: any) => void;
}

export function SoverentityFrontend({ 
  existingIdentity, 
  onIdentityUpdate 
}: SoverentityFrontendProps) {
  const [identity, setIdentity] = useState(existingIdentity || null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    email: '',
  });

  const [verificationState, setVerificationState] = useState({
    loading: false,
    error: null,
    status: identity?.verification?.status || identity?.identity?.verification?.status || 'unverified'
  });

  const [verificationCode, setVerificationCode] = useState('');

  // Update internal state when existingIdentity prop changes
  useEffect(() => {
    if (existingIdentity) {
      console.log('SoverentityFrontend received identity:', existingIdentity);
      setIdentity(existingIdentity);
      
      // Extract verification status from the nested structure
      const verificationStatus = existingIdentity?.verification?.status || 
                               existingIdentity?.identity?.verification?.status || 
                               'unverified';
      
      setVerificationState(prev => ({
        ...prev,
        status: verificationStatus
      }));
    }
  }, [existingIdentity]);

  // Helper function to safely extract identity data
  const getIdentityData = (identity: any) => {
    if (!identity) return null;
    
    // Try different possible structures
    const identityData = identity?.identity?.identity || identity?.identity || identity;
    const fingerprint = identity?.fingerprint || identityData?.fingerprint;
    
    return {
      name: identityData?.name,
      email: identityData?.email,
      fingerprint: fingerprint,
      verification: identity?.verification || identity?.identity?.verification || { status: 'unverified' }
    };
  };

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

      if (!response.ok) {
        throw new Error(data.error || 'Failed to create identity');
      }

      console.log('Created identity response:', data);
      
      // Update both local state and parent component
      setIdentity(data.identity || data);
      if (onIdentityUpdate) {
        onIdentityUpdate(data.identity || data);
      }
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

      console.log('Starting verification for identity:', identity);
      
      const identityData = getIdentityData(identity);
      if (!identityData) {
        throw new Error('No identity data available');
      }

      const payload = {
        fingerprint: identityData.fingerprint,
        type: 'email',
        value: identityData.email
      };
      
      console.log('Sending verification payload:', payload);

      const response = await fetch('/api/identity/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload)
      });

      console.log('Verification response status:', response.status);
      const data = await response.json();
      console.log('Verification response data:', data);

      if (!response.ok) {
        throw new Error(data.error || 'Verification failed');
      }

      setVerificationState(prev => ({ 
        ...prev, 
        status: 'verification_sent',
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

      const identityData = getIdentityData(identity);
      if (!identityData) {
        throw new Error('No identity data available');
      }

      const response = await fetch('/api/identity/verify', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fingerprint: identityData.fingerprint,
          code: verificationCode
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Code verification failed');
      }

      // Update both local state and parent component
      setVerificationState(prev => ({ 
        ...prev, 
        status: 'verified',
        loading: false 
      }));
      
      setIdentity(data.identity);
      if (onIdentityUpdate) {
        onIdentityUpdate(data.identity);
      }
    } catch (err) {
      setVerificationState(prev => ({ 
        ...prev, 
        error: err instanceof Error ? err.message : 'Code verification failed',
        loading: false 
      }));
    }
  };

  // Render the fingerprint in formatted groups
  const formatFingerprint = (fingerprint) => {
    if (!fingerprint) return 'No fingerprint';
    return fingerprint?.match(/.{1,4}/g)?.join(' ') || fingerprint;
  };

  const identityData = getIdentityData(identity);

  return (
    <Card className="w-full shadow-md overflow-hidden">
      <CardHeader className="bg-gradient-to-r from-indigo-50 to-sky-50 dark:from-indigo-950/30 dark:to-sky-950/30">
        <div className="flex items-center gap-3">
          <div className="bg-white dark:bg-slate-800 rounded-full p-2 shadow-sm">
            <Shield className="h-6 w-6 text-indigo-600 dark:text-indigo-400" />
          </div>
          <CardTitle className="text-xl sm:text-2xl">Sovereign Identity</CardTitle>
        </div>
        <CardDescription className="mt-2">
          Create and control your digital identity with PGP encryption. Your keys, your data.
        </CardDescription>
      </CardHeader>
      
      <CardContent className="p-5 sm:p-6">
        {error && (
          <Alert variant="destructive" className="mb-6">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {!identity ? (
          <div className="space-y-6 max-w-md mx-auto py-4">
            <div className="bg-indigo-50 dark:bg-indigo-950/30 rounded-xl p-5 text-center mb-6">
              <Key className="h-10 w-10 mx-auto mb-3 text-indigo-600 dark:text-indigo-400" />
              <h3 className="text-lg font-medium mb-2">Create Your Digital Identity</h3>
              <p className="text-sm text-slate-600 dark:text-slate-400">
                Generate a secure PGP keypair that you control. Your identity stays private and secure.
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium mb-1 text-slate-700 dark:text-slate-300">Full Name</label>
              <Input
                placeholder="Your name"
                className="bg-white dark:bg-slate-900"
                value={formData.name}
                onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1 text-slate-700 dark:text-slate-300">Email Address</label>
              <Input
                type="email"
                placeholder="your.email@example.com"
                className="bg-white dark:bg-slate-900"
                value={formData.email}
                onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
              />
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                We'll verify this email to confirm your identity
              </p>
            </div>

            <Button 
              onClick={handleCreateIdentity}
              className="w-full bg-indigo-600 hover:bg-indigo-700 text-white py-2 h-auto"
              disabled={loading || !formData.name || !formData.email}
            >
              {loading ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  Creating Identity...
                </>
              ) : (
                <>
                  <Key className="h-4 w-4 mr-2" />
                  Create Sovereign Identity
                </>
              )}
            </Button>
          </div>
        ) : (
          <div className="space-y-6">
            <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
              <div className="bg-slate-50 dark:bg-slate-900 p-4 border-b dark:border-slate-800">
                <div className="flex items-center gap-3">
                  <div className={`rounded-full p-1.5 ${
                    identityData?.verification?.status === 'verified' 
                      ? 'bg-green-100 dark:bg-green-900/30' 
                      : 'bg-yellow-100 dark:bg-yellow-900/30'
                  }`}>
                    <Key className={`h-5 w-5 ${
                      identityData?.verification?.status === 'verified'
                        ? 'text-green-600 dark:text-green-500'
                        : 'text-yellow-600 dark:text-yellow-500'
                    }`} />
                  </div>
                  <div>
                    <h3 className="font-medium">{identityData?.name || 'Unknown'}</h3>
                    <div className="flex items-center text-sm text-slate-600 dark:text-slate-400">
                      <Mail className="h-3.5 w-3.5 mr-1 inline" />
                      {identityData?.email || 'No email'}
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="p-4">
                <div className="mb-4">
                  <div className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center">
                    <Fingerprint className="h-4 w-4 mr-1" /> 
                    PGP Fingerprint
                  </div>
                  <div className="font-mono text-xs tracking-wider text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-800 p-2 rounded border border-slate-200 dark:border-slate-700 break-all">
                    {formatFingerprint(identityData?.fingerprint)}
                  </div>
                </div>
                
                <div className="flex items-center gap-2">
                  <div className={`flex-shrink-0 rounded-full h-6 w-6 flex items-center justify-center ${
                    identityData?.verification?.status === 'verified'
                      ? 'bg-green-100 dark:bg-green-900/30'
                      : 'bg-yellow-100 dark:bg-yellow-900/30'
                  }`}>
                    {identityData?.verification?.status === 'verified' ? (
                      <CheckCircle2 className="h-4 w-4 text-green-600 dark:text-green-500" />
                    ) : (
                      <Lock className="h-4 w-4 text-yellow-600 dark:text-yellow-500" />
                    )}
                  </div>
                  <div className="text-sm">
                    <span className="font-medium">Status: </span>
                    <span className={
                      identityData?.verification?.status === 'verified'
                        ? 'text-green-600 dark:text-green-500 font-medium'
                        : 'text-yellow-600 dark:text-yellow-500 font-medium'
                    }>
                      {identityData?.verification?.status || 'unverified'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {identityData?.verification?.status !== 'verified' && (
              <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5">
                <h3 className="text-base font-medium mb-4">Verify Your Identity</h3>
                
                {verificationState.status === 'verification_sent' ? (
                  <div className="space-y-4">
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      We've sent a verification code to your email. Enter it below to verify your identity.
                    </p>
                    <Input
                      placeholder="Enter verification code"
                      value={verificationCode}
                      onChange={(e) => setVerificationCode(e.target.value)}
                      maxLength={6}
                      className="text-center tracking-wider font-mono text-lg"
                    />
                    <Button
                      onClick={handleVerifyCode}
                      disabled={verificationState.loading || !verificationCode}
                      className="w-full bg-indigo-600 hover:bg-indigo-700 text-white"
                    >
                      {verificationState.loading ? (
                        <>
                          <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                          Verifying...
                        </>
                      ) : (
                        <>
                          <CheckCircle2 className="h-4 w-4 mr-2" />
                          Verify Identity
                        </>
                      )}
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      Verify your email address to prove ownership of this identity.
                    </p>
                    <Button
                      onClick={handleVerification}
                      disabled={verificationState.loading}
                      className="w-full bg-indigo-600 hover:bg-indigo-700 text-white"
                    >
                      {verificationState.loading ? (
                        <>
                          <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                          Sending Code...
                        </>
                      ) : (
                        <>
                          <Mail className="h-4 w-4 mr-2" />
                          Send Verification Email
                        </>
                      )}
                    </Button>
                  </div>
                )}
                
                {verificationState.error && (
                  <Alert variant="destructive" className="mt-4">
                    <AlertDescription>{verificationState.error}</AlertDescription>
                  </Alert>
                )}
              </div>
            )}

            {identityData?.verification?.status === 'verified' && (
              <Alert className="bg-green-50 dark:bg-green-900/20 border-green-100 dark:border-green-900 text-green-800 dark:text-green-300">
                <CheckCircle2 className="h-4 w-4 mr-2" />
                <AlertDescription>
                  Your identity has been successfully verified!
                </AlertDescription>
              </Alert>
            )}
          </div>
        )}
      </CardContent>
      
      {!identity && (
        <CardFooter className="bg-slate-50 dark:bg-slate-900 border-t px-6 py-4">
          <p className="text-xs text-slate-500 dark:text-slate-400 w-full text-center">
            Your keys are generated securely in your browser and never leave your device.
            We only store your public key and encrypted information you choose to share.
          </p>
        </CardFooter>
      )}
    </Card>
  );
}