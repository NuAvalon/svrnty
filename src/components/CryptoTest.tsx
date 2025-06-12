// src/components/CryptoTest.tsx
"use client";

import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { CheckCircle2, XCircle, AlertTriangle, RefreshCw } from 'lucide-react';

interface CryptoTestResult {
  test: string;
  status: 'pass' | 'fail' | 'warn';
  message: string;
  details?: any;
}

export function CryptoTest() {
  const [isClient, setIsClient] = useState(false);
  const [testResults, setTestResults] = useState<CryptoTestResult[]>([]);
  const [isRunning, setIsRunning] = useState(false);

  useEffect(() => {
    setIsClient(true);
  }, []);

  const runCryptoTests = async () => {
    if (!isClient) return;
    
    setIsRunning(true);
    const results: CryptoTestResult[] = [];

    // Test 1: Basic environment check
    results.push({
      test: 'Browser Environment',
      status: typeof window !== 'undefined' ? 'pass' : 'fail',
      message: typeof window !== 'undefined' ? 'Running in browser' : 'Not in browser environment'
    });

    // Test 2: HTTPS/Secure Context
    const isSecureContext = window?.isSecureContext;
    const protocol = window?.location?.protocol;
    results.push({
      test: 'Secure Context',
      status: isSecureContext ? 'pass' : (protocol === 'http:' && window?.location?.hostname === 'localhost') ? 'warn' : 'fail',
      message: isSecureContext ? 'Secure context (HTTPS)' : `Insecure context (${protocol}) - ${window?.location?.hostname}`,
      details: { isSecureContext, protocol, hostname: window?.location?.hostname }
    });

    // Test 3: Global crypto availability
    const hasGlobalCrypto = typeof crypto !== 'undefined';
    const hasGlobalSubtle = hasGlobalCrypto && typeof crypto.subtle !== 'undefined';
    results.push({
      test: 'Global Crypto API',
      status: hasGlobalSubtle ? 'pass' : 'fail',
      message: hasGlobalSubtle ? 'Global crypto.subtle available' : hasGlobalCrypto ? 'crypto exists but crypto.subtle is undefined' : 'crypto is undefined',
      details: { hasGlobalCrypto, hasGlobalSubtle, cryptoType: typeof crypto, subtleType: typeof crypto?.subtle }
    });

    // Test 4: Window crypto availability
    const hasWindowCrypto = typeof window?.crypto !== 'undefined';
    const hasWindowSubtle = hasWindowCrypto && typeof window.crypto.subtle !== 'undefined';
    results.push({
      test: 'Window Crypto API',
      status: hasWindowSubtle ? 'pass' : 'fail',
      message: hasWindowSubtle ? 'window.crypto.subtle available' : hasWindowCrypto ? 'window.crypto exists but subtle is undefined' : 'window.crypto is undefined',
      details: { hasWindowCrypto, hasWindowSubtle }
    });

    // Test 5: GlobalThis crypto
    const hasGlobalThisCrypto = typeof globalThis?.crypto !== 'undefined';
    const hasGlobalThisSubtle = hasGlobalThisCrypto && typeof globalThis.crypto.subtle !== 'undefined';
    results.push({
      test: 'GlobalThis Crypto API',
      status: hasGlobalThisSubtle ? 'pass' : 'warn',
      message: hasGlobalThisSubtle ? 'globalThis.crypto.subtle available' : 'Not available (fallback only)',
      details: { hasGlobalThisCrypto, hasGlobalThisSubtle }
    });

    // Test 6: Basic crypto functionality
    try {
      let cryptoAPI = null;
      if (hasGlobalSubtle) cryptoAPI = crypto;
      else if (hasWindowSubtle) cryptoAPI = window.crypto;
      else if (hasGlobalThisSubtle) cryptoAPI = globalThis.crypto;

      if (cryptoAPI) {
        const testArray = new Uint8Array(16);
        cryptoAPI.getRandomValues(testArray);
        
        results.push({
          test: 'Random Number Generation',
          status: 'pass',
          message: 'getRandomValues() working',
          details: { testArray: Array.from(testArray) }
        });
      } else {
        results.push({
          test: 'Random Number Generation',
          status: 'fail',
          message: 'No crypto API available for testing'
        });
      }
    } catch (error) {
      results.push({
        test: 'Random Number Generation',
        status: 'fail',
        message: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: { error }
      });
    }

    // Test 7: SubtleCrypto operations
    try {
      let cryptoAPI = null;
      if (hasGlobalSubtle) cryptoAPI = crypto;
      else if (hasWindowSubtle) cryptoAPI = window.crypto;
      else if (hasGlobalThisSubtle) cryptoAPI = globalThis.crypto;

      if (cryptoAPI?.subtle) {
        // Test key generation
        const key = await cryptoAPI.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );
        
        results.push({
          test: 'SubtleCrypto Key Generation',
          status: 'pass',
          message: 'Successfully generated AES key',
          details: { keyType: key.type, keyAlgorithm: key.algorithm }
        });
      } else {
        results.push({
          test: 'SubtleCrypto Key Generation',
          status: 'fail',
          message: 'No SubtleCrypto API available'
        });
      }
    } catch (error) {
      results.push({
        test: 'SubtleCrypto Key Generation',
        status: 'fail',
        message: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: { error }
      });
    }

    // Test 8: OpenPGP loading
    try {
      const openpgp = await import('openpgp');
      results.push({
        test: 'OpenPGP Library',
        status: 'pass',
        message: 'OpenPGP loaded successfully',
        details: { version: openpgp.config?.version }
      });
    } catch (error) {
      results.push({
        test: 'OpenPGP Library',
        status: 'fail',
        message: `Failed to load OpenPGP: ${error instanceof Error ? error.message : 'Unknown error'}`,
        details: { error }
      });
    }

    setTestResults(results);
    setIsRunning(false);
  };

  const getStatusIcon = (status: 'pass' | 'fail' | 'warn') => {
    switch (status) {
      case 'pass':
        return <CheckCircle2 className="h-4 w-4 text-green-600" />;
      case 'fail':
        return <XCircle className="h-4 w-4 text-red-600" />;
      case 'warn':
        return <AlertTriangle className="h-4 w-4 text-yellow-600" />;
    }
  };

  const getStatusColor = (status: 'pass' | 'fail' | 'warn') => {
    switch (status) {
      case 'pass':
        return 'border-green-200 bg-green-50 dark:border-green-800 dark:bg-green-950/30';
      case 'fail':
        return 'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-950/30';
      case 'warn':
        return 'border-yellow-200 bg-yellow-50 dark:border-yellow-800 dark:bg-yellow-950/30';
    }
  };

  if (!isClient) {
    return (
      <Card className="w-full max-w-4xl mx-auto">
        <CardContent className="p-8 text-center">
          <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-4 text-blue-600" />
          <p>Loading crypto test component...</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-4xl mx-auto">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <AlertTriangle className="h-6 w-6 text-blue-600" />
          Crypto API Diagnostics
        </CardTitle>
      </CardHeader>
      
      <CardContent className="space-y-4">
        <div className="flex justify-between items-center">
          <p className="text-sm text-muted-foreground">
            Test Web Crypto API availability and functionality
          </p>
          <Button 
            onClick={runCryptoTests} 
            disabled={isRunning}
            className="bg-blue-600 hover:bg-blue-700"
          >
            {isRunning ? (
              <>
                <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                Running Tests...
              </>
            ) : (
              'Run Crypto Tests'
            )}
          </Button>
        </div>

        {testResults.length > 0 && (
          <div className="space-y-3">
            <h3 className="text-lg font-semibold">Test Results:</h3>
            
            {testResults.map((result, index) => (
              <div 
                key={index}
                className={`border rounded-lg p-4 ${getStatusColor(result.status)}`}
              >
                <div className="flex items-start gap-3">
                  {getStatusIcon(result.status)}
                  <div className="flex-1">
                    <div className="flex justify-between items-start">
                      <h4 className="font-medium">{result.test}</h4>
                      <span className={`text-xs px-2 py-1 rounded ${
                        result.status === 'pass' ? 'bg-green-100 text-green-800' :
                        result.status === 'fail' ? 'bg-red-100 text-red-800' :
                        'bg-yellow-100 text-yellow-800'
                      }`}>
                        {result.status.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-sm mt-1">{result.message}</p>
                    
                    {result.details && (
                      <details className="mt-2">
                        <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">
                          View Details
                        </summary>
                        <pre className="text-xs mt-2 p-2 bg-muted rounded overflow-auto">
                          {JSON.stringify(result.details, null, 2)}
                        </pre>
                      </details>
                    )}
                  </div>
                </div>
              </div>
            ))}

            {/* Summary */}
            <div className="mt-6 p-4 border rounded-lg bg-slate-50 dark:bg-slate-900">
              <h4 className="font-medium mb-2">Summary & Recommendations:</h4>
              <div className="text-sm space-y-2">
                {testResults.some(r => r.status === 'fail') && (
                  <Alert variant="destructive">
                    <XCircle className="h-4 w-4" />
                    <AlertDescription>
                      <strong>Critical Issues Found:</strong>
                      <ul className="list-disc list-inside mt-2 space-y-1">
                        {testResults
                          .filter(r => r.status === 'fail')
                          .map((r, i) => (
                            <li key={i}>{r.test}: {r.message}</li>
                          ))
                        }
                      </ul>
                    </AlertDescription>
                  </Alert>
                )}
                
                {testResults.some(r => r.status === 'warn') && (
                  <Alert>
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>
                      <strong>Warnings:</strong>
                      <ul className="list-disc list-inside mt-2 space-y-1">
                        {testResults
                          .filter(r => r.status === 'warn')
                          .map((r, i) => (
                            <li key={i}>{r.test}: {r.message}</li>
                          ))
                        }
                      </ul>
                    </AlertDescription>
                  </Alert>
                )}

                {testResults.every(r => r.status === 'pass') && (
                  <Alert>
                    <CheckCircle2 className="h-4 w-4" />
                    <AlertDescription>
                      <strong>All tests passed!</strong> Your browser fully supports the required crypto APIs.
                    </AlertDescription>
                  </Alert>
                )}

                <div className="mt-4 text-xs text-muted-foreground">
                  <p><strong>Common Issues:</strong></p>
                  <ul className="list-disc list-inside space-y-1">
                    <li>HTTP sites (non-localhost) don't support Web Crypto API - use HTTPS</li>
                    <li>Some older browsers don't support SubtleCrypto</li>
                    <li>Incognito/private browsing may have restrictions</li>
                    <li>Browser extensions can interfere with crypto APIs</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}