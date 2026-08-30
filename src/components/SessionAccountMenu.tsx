'use client';

/**
 * Account menu — lock, switch identity, password-gated delete local copy.
 * UI-only; uses client-store session helpers (no crypto changes).
 */

import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { ChevronDown, LogOut, RefreshCw, Trash2 } from 'lucide-react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import {
  clearAll,
  initSessionKey,
  listIdentities,
  lockSession,
  setActiveFingerprint,
} from '@/lib/identity/client-store';

type IdentityOption = { name: string; fingerprint: string };

export function SessionAccountMenu({
  activeFingerprint,
  activeName,
  onLocked,
}: {
  activeFingerprint: string;
  activeName?: string;
  onLocked: () => void;
}) {
  const [others, setOthers] = useState<IdentityOption[]>([]);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [passphrase, setPassphrase] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const all = await listIdentities();
        if (cancelled) return;
        setOthers(
          all
            .map((r: { fingerprint: string; data?: { identity?: { name?: string } } }) => ({
              name: r.data?.identity?.name || 'Identity',
              fingerprint: r.fingerprint,
            }))
            .filter((o) => o.fingerprint !== activeFingerprint),
        );
      } catch {
        if (!cancelled) setOthers([]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeFingerprint]);

  const handleLock = () => {
    lockSession();
    onLocked();
  };

  const handleSwitch = async (fp: string) => {
    lockSession();
    await setActiveFingerprint(fp);
    onLocked();
  };

  const handleDeleteLocal = async () => {
    setBusy(true);
    setError(null);
    try {
      // Re-enter passphrase before nuclear wipe (export-behind-auth pattern).
      await initSessionKey(passphrase);
      await clearAll('I understand this deletes all keys');
      lockSession();
      setDeleteOpen(false);
      setPassphrase('');
      onLocked();
      if (typeof window !== 'undefined') window.location.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not delete local copy');
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            type="button"
            variant="outline"
            size="sm"
            data-testid="session-account-menu"
            style={{
              fontFamily: E.fontSans,
              fontSize: 12,
              borderColor: E.border,
              color: E.text,
              background: 'transparent',
            }}
          >
            {activeName || 'Account'}
            <ChevronDown className="ml-1.5 h-3.5 w-3.5 opacity-70" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent
          align="end"
          className="w-56"
          style={{
            background: E.surfaceSolid,
            border: `1px solid ${E.border}`,
            color: E.text,
            fontFamily: E.fontSans,
          }}
        >
          <DropdownMenuItem
            onClick={handleLock}
            style={{ fontFamily: E.fontSans, cursor: 'pointer' }}
          >
            <LogOut className="mr-2 h-4 w-4" /> Lock / log out
          </DropdownMenuItem>
          {others.map((o) => (
            <DropdownMenuItem
              key={o.fingerprint}
              onClick={() => {
                void handleSwitch(o.fingerprint);
              }}
              style={{ fontFamily: E.fontSans, cursor: 'pointer' }}
            >
              <RefreshCw className="mr-2 h-4 w-4" /> Switch to {o.name}
            </DropdownMenuItem>
          ))}
          <DropdownMenuSeparator />
          <DropdownMenuItem
            onClick={() => {
              setError(null);
              setPassphrase('');
              setDeleteOpen(true);
            }}
            className="text-red-400 focus:text-red-300"
            style={{ fontFamily: E.fontSans, cursor: 'pointer' }}
          >
            <Trash2 className="mr-2 h-4 w-4" /> Delete local copy…
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <DialogContent
          style={{
            background: E.surfaceSolid,
            border: `1px solid ${E.border}`,
            color: E.text,
            fontFamily: E.fontSans,
          }}
        >
          <DialogHeader>
            <DialogTitle>Delete local copy</DialogTitle>
            <DialogDescription style={{ color: E.muted }}>
              This erases keys and contacts stored in this browser. It cannot be undone without a
              recovery backup. Re-enter your passphrase to confirm.
            </DialogDescription>
          </DialogHeader>
          {error ? (
            <p style={{ margin: 0, fontSize: 12, color: E.danger }}>{error}</p>
          ) : null}
          <Input
            type="password"
            autoComplete="current-password"
            placeholder="Passphrase"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            style={{ fontFamily: E.fontSans }}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteOpen(false)} disabled={busy}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={busy || passphrase.length < 1}
              onClick={() => {
                void handleDeleteLocal();
              }}
            >
              {busy ? 'Deleting…' : 'Delete local copy'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
