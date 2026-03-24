"use client";

import React, { useState, useCallback } from 'react';
import {
  formatSignalMessage,
  parseSignalMessage,
  SignalTransport,
  getAvailableTransports,
} from '@/lib/trust/transport';
import type { SignedSignal, TrustSignal } from '@/lib/trust/types';

// --- Signal Composer ---

interface SignalComposerProps {
  /** Current user's fingerprint */
  myFingerprint: string;
  /** Known contacts for recipient picker */
  contacts: Array<{ fingerprint: string; name: string; trusted: boolean; signalHandle?: string }>;
  /** Called when a signal is ready to send (caller handles crypto signing) */
  onSend: (payload: TrustSignal, recipientFingerprint: string) => Promise<SignedSignal>;
}

type SignalType = 'vouch' | 'break' | 'concern' | 'introduce';

export function SignalComposer({ myFingerprint, contacts, onSend }: SignalComposerProps) {
  const [signalType, setSignalType] = useState<SignalType>('vouch');
  const [recipient, setRecipient] = useState('');
  const [subject, setSubject] = useState('');
  const [detail, setDetail] = useState('');
  const [reason, setReason] = useState('');
  const [introName, setIntroName] = useState('');
  const [introPubKey, setIntroPubKey] = useState('');
  const [sending, setSending] = useState(false);
  const [result, setResult] = useState<{ success: boolean; message: string } | null>(null);
  const [previewSignal, setPreviewSignal] = useState<string | null>(null);

  const buildPayload = useCallback((): TrustSignal | null => {
    switch (signalType) {
      case 'vouch':
        if (!subject) return null;
        return { type: 'vouch', subject };
      case 'break':
        if (!subject) return null;
        return { type: 'break', subject, reason: reason || undefined };
      case 'concern':
        if (!subject || !detail) return null;
        return { type: 'concern', subject, detail };
      case 'introduce':
        if (!subject || !introName || !introPubKey) return null;
        return { type: 'introduce', subject, pub_key: introPubKey, name: introName };
      default:
        return null;
    }
  }, [signalType, subject, detail, reason, introName, introPubKey]);

  const handleSend = async (transportName: string) => {
    const payload = buildPayload();
    if (!payload || !recipient) return;

    setSending(true);
    setResult(null);

    try {
      const signed = await onSend(payload, recipient);
      const transports = getAvailableTransports();
      const transport = transports.find(t => t.name === transportName);

      if (!transport) {
        setResult({ success: false, message: `Transport "${transportName}" not available` });
        return;
      }

      const contact = contacts.find(c => c.fingerprint === recipient);
      const handle = contact?.signalHandle || '';
      const success = await transport.send(signed, handle);

      if (success) {
        setResult({ success: true, message: `Signal sent via ${transportName}` });
      } else {
        setResult({ success: false, message: 'Send cancelled or failed' });
      }
    } catch (err) {
      setResult({ success: false, message: (err as Error).message });
    } finally {
      setSending(false);
    }
  };

  const handlePreview = async () => {
    const payload = buildPayload();
    if (!payload || !recipient) return;

    try {
      const signed = await onSend(payload, recipient);
      setPreviewSignal(formatSignalMessage(signed));
    } catch (err) {
      setResult({ success: false, message: (err as Error).message });
    }
  };

  return (
    <div style={styles.container}>
      <h3 style={styles.title}>Send Trust Signal</h3>

      {/* Signal Type */}
      <div style={styles.field}>
        <label style={styles.label}>TYPE</label>
        <div style={styles.typeGrid}>
          {(['vouch', 'break', 'concern', 'introduce'] as const).map(t => (
            <button
              key={t}
              onClick={() => { setSignalType(t); setResult(null); setPreviewSignal(null); }}
              style={{
                ...styles.typeBtn,
                ...(signalType === t ? styles.typeBtnActive : {}),
                ...(signalType === t && t === 'break' ? { borderColor: '#9a5a5a', color: '#d47a7a', background: 'rgba(154, 90, 90, 0.1)' } : {}),
              }}
            >
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Recipient */}
      <div style={styles.field}>
        <label style={styles.label}>TO</label>
        <select
          value={recipient}
          onChange={e => setRecipient(e.target.value)}
          style={styles.select}
        >
          <option value="">Select recipient...</option>
          {contacts.map(c => (
            <option key={c.fingerprint} value={c.fingerprint}>
              {c.name} {c.trusted ? '(trusted)' : '(known)'} ({c.fingerprint.slice(0, 8)}...)
            </option>
          ))}
        </select>
      </div>

      {/* Subject (vouch, break, concern, introduce) */}
      <div style={styles.field}>
        <label style={styles.label}>
          {signalType === 'introduce' ? 'SUBJECT FINGERPRINT' : 'ABOUT (fingerprint)'}
        </label>
        <input
          type="text"
          value={subject}
          onChange={e => setSubject(e.target.value)}
          placeholder="Fingerprint of the person this signal is about"
          style={styles.input}
        />
      </div>

      {/* Reason (break) */}
      {signalType === 'break' && (
        <div style={styles.field}>
          <label style={styles.label}>REASON (optional)</label>
          <input
            type="text"
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder="Why are you breaking trust?"
            style={styles.input}
          />
        </div>
      )}

      {/* Detail (concern) */}
      {signalType === 'concern' && (
        <div style={styles.field}>
          <label style={styles.label}>DETAIL</label>
          <textarea
            value={detail}
            onChange={e => setDetail(e.target.value)}
            placeholder="What is the concern?"
            rows={3}
            style={{ ...styles.input, resize: 'vertical' as const }}
          />
        </div>
      )}

      {/* Introduction fields */}
      {signalType === 'introduce' && (
        <>
          <div style={styles.field}>
            <label style={styles.label}>NAME</label>
            <input
              type="text"
              value={introName}
              onChange={e => setIntroName(e.target.value)}
              placeholder="Display name for the person"
              style={styles.input}
            />
          </div>
          <div style={styles.field}>
            <label style={styles.label}>PUBLIC KEY</label>
            <textarea
              value={introPubKey}
              onChange={e => setIntroPubKey(e.target.value)}
              placeholder="Their PGP public key (armored)"
              rows={3}
              style={{ ...styles.input, resize: 'vertical' as const, fontFamily: 'monospace', fontSize: '11px' }}
            />
          </div>
        </>
      )}

      {/* Preview */}
      {previewSignal && (
        <div style={styles.preview}>
          <label style={styles.label}>PREVIEW</label>
          <pre style={styles.previewText}>{previewSignal}</pre>
        </div>
      )}

      {/* Result */}
      {result && (
        <div style={{
          ...styles.result,
          borderColor: result.success ? '#6a9a6a' : '#9a5a5a',
          color: result.success ? '#6a9a6a' : '#d47a7a',
        }}>
          {result.message}
        </div>
      )}

      {/* Actions */}
      <div style={styles.actions}>
        <button onClick={handlePreview} style={styles.previewBtn} disabled={sending || !recipient}>
          Preview
        </button>
        <button
          onClick={() => handleSend('Signal')}
          style={{ ...styles.sendBtn, ...styles.signalBtn }}
          disabled={sending || !recipient || !buildPayload()}
        >
          {sending ? 'Sending...' : 'Share via Signal'}
        </button>
        <button
          onClick={() => handleSend('Clipboard')}
          style={styles.sendBtn}
          disabled={sending || !recipient || !buildPayload()}
        >
          Copy to Clipboard
        </button>
      </div>
    </div>
  );
}

// --- Signal Receiver ---

interface SignalReceiverProps {
  onReceive: (signal: SignedSignal) => Promise<{ valid: boolean; senderName?: string }>;
}

export function SignalReceiver({ onReceive }: SignalReceiverProps) {
  const [input, setInput] = useState('');
  const [result, setResult] = useState<{
    valid: boolean;
    signal?: SignedSignal;
    senderName?: string;
    error?: string;
  } | null>(null);
  const [verifying, setVerifying] = useState(false);

  const handleVerify = async () => {
    if (!input.trim()) return;

    setVerifying(true);
    setResult(null);

    const parsed = parseSignalMessage(input);
    if (!parsed) {
      setResult({ valid: false, error: 'Could not parse signal. Check the format.' });
      setVerifying(false);
      return;
    }

    try {
      const verification = await onReceive(parsed);
      setResult({
        valid: verification.valid,
        signal: parsed,
        senderName: verification.senderName,
        error: verification.valid ? undefined : 'Signature verification failed',
      });
    } catch (err) {
      setResult({ valid: false, error: (err as Error).message });
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div style={styles.container}>
      <h3 style={styles.title}>Verify Trust Signal</h3>

      <div style={styles.field}>
        <label style={styles.label}>PASTE RECEIVED SIGNAL</label>
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder={"Paste the trust signal message here...\n\nAccepts both formatted messages and raw JSON."}
          rows={8}
          style={{ ...styles.input, fontFamily: 'monospace', fontSize: '11px' }}
        />
      </div>

      <button
        onClick={handleVerify}
        style={styles.sendBtn}
        disabled={verifying || !input.trim()}
      >
        {verifying ? 'Verifying...' : 'Verify Signal'}
      </button>

      {result && (
        <div style={{
          ...styles.verifyResult,
          borderColor: result.valid ? '#6a9a6a' : '#9a5a5a',
        }}>
          <div style={{
            fontSize: '14px',
            fontWeight: 600,
            color: result.valid ? '#6a9a6a' : '#d47a7a',
            marginBottom: '8px',
          }}>
            {result.valid ? 'VERIFIED' : 'FAILED'}
          </div>

          {result.error && (
            <div style={{ color: '#d47a7a', fontSize: '12px', marginBottom: '8px' }}>
              {result.error}
            </div>
          )}

          {result.signal && result.valid && (
            <div style={{ fontSize: '12px', color: '#a09880' }}>
              <div><strong>Type:</strong> {result.signal.payload.type}</div>
              <div><strong>From:</strong> {result.senderName || result.signal.from.slice(0, 16) + '...'}</div>
              <div><strong>Time:</strong> {new Date(result.signal.timestamp).toLocaleString()}</div>
              {result.signal.pq_signature && (
                <div style={{ color: '#4ecdc4', marginTop: '4px' }}>
                  Post-quantum signature present
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// --- Signal Link Component ---

interface SignalLinkProps {
  handle: string;
  name: string;
}

export function SignalLink({ handle, name }: SignalLinkProps) {
  const link = SignalTransport.userLink(handle);
  return (
    <a
      href={link}
      target="_blank"
      rel="noopener noreferrer"
      style={styles.signalLink}
      title={`Message ${name} on Signal`}
    >
      Signal: @{handle}
    </a>
  );
}

// --- Styles ---

const styles: Record<string, React.CSSProperties> = {
  container: {
    background: 'rgba(15, 15, 25, 0.92)',
    border: '1px solid rgba(180, 160, 100, 0.2)',
    borderRadius: '12px',
    padding: '24px',
    fontFamily: "'SF Mono', 'Fira Code', monospace",
    color: '#e0dcd0',
    maxWidth: '480px',
  },
  title: {
    fontSize: '14px',
    color: '#c8a84e',
    letterSpacing: '2px',
    textTransform: 'uppercase' as const,
    marginBottom: '20px',
    paddingBottom: '8px',
    borderBottom: '1px solid rgba(180, 160, 100, 0.15)',
  },
  field: {
    marginBottom: '16px',
  },
  label: {
    display: 'block',
    fontSize: '10px',
    color: '#8a8070',
    letterSpacing: '1.5px',
    textTransform: 'uppercase' as const,
    marginBottom: '6px',
  },
  input: {
    width: '100%',
    background: 'rgba(10, 10, 15, 0.8)',
    border: '1px solid rgba(180, 160, 100, 0.2)',
    borderRadius: '6px',
    padding: '10px 12px',
    color: '#e0dcd0',
    fontSize: '13px',
    fontFamily: "'SF Mono', 'Fira Code', monospace",
    outline: 'none',
  },
  select: {
    width: '100%',
    background: 'rgba(10, 10, 15, 0.8)',
    border: '1px solid rgba(180, 160, 100, 0.2)',
    borderRadius: '6px',
    padding: '10px 12px',
    color: '#e0dcd0',
    fontSize: '13px',
    fontFamily: "'SF Mono', 'Fira Code', monospace",
    outline: 'none',
  },
  typeGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(4, 1fr)',
    gap: '6px',
  },
  typeBtn: {
    background: 'transparent',
    border: '1px solid rgba(180, 160, 100, 0.2)',
    borderRadius: '6px',
    padding: '8px 4px',
    color: '#8a8070',
    fontSize: '11px',
    cursor: 'pointer',
    transition: 'all 0.2s',
    fontFamily: "'SF Mono', 'Fira Code', monospace",
  },
  typeBtnActive: {
    borderColor: '#c8a84e',
    color: '#c8a84e',
    background: 'rgba(200, 168, 78, 0.1)',
  },
  preview: {
    marginBottom: '16px',
  },
  previewText: {
    background: 'rgba(10, 10, 15, 0.9)',
    border: '1px solid rgba(180, 160, 100, 0.15)',
    borderRadius: '6px',
    padding: '12px',
    fontSize: '11px',
    lineHeight: '1.5',
    whiteSpace: 'pre-wrap' as const,
    wordBreak: 'break-all' as const,
    overflowX: 'auto' as const,
    color: '#a09880',
    maxHeight: '200px',
    overflowY: 'auto' as const,
  },
  actions: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap' as const,
  },
  previewBtn: {
    flex: '0 0 auto',
    background: 'transparent',
    border: '1px solid rgba(180, 160, 100, 0.3)',
    borderRadius: '6px',
    padding: '10px 16px',
    color: '#8a8070',
    fontSize: '12px',
    cursor: 'pointer',
    fontFamily: "'SF Mono', 'Fira Code', monospace",
  },
  sendBtn: {
    flex: '1',
    background: 'rgba(200, 168, 78, 0.15)',
    border: '1px solid rgba(200, 168, 78, 0.3)',
    borderRadius: '6px',
    padding: '10px 16px',
    color: '#c8a84e',
    fontSize: '12px',
    cursor: 'pointer',
    fontFamily: "'SF Mono', 'Fira Code', monospace",
    transition: 'all 0.2s',
  },
  signalBtn: {
    background: 'rgba(58, 118, 240, 0.15)',
    borderColor: 'rgba(58, 118, 240, 0.3)',
    color: '#6a9af0',
  },
  result: {
    marginBottom: '12px',
    padding: '8px 12px',
    borderRadius: '6px',
    border: '1px solid',
    fontSize: '12px',
  },
  verifyResult: {
    marginTop: '16px',
    padding: '16px',
    borderRadius: '8px',
    border: '1px solid',
    background: 'rgba(10, 10, 15, 0.6)',
  },
  signalLink: {
    color: '#6a9af0',
    textDecoration: 'none',
    fontSize: '12px',
    borderBottom: '1px dotted rgba(106, 154, 240, 0.3)',
  },
};
