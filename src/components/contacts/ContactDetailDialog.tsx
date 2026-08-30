'use client';

/**
 * Compact contact card — phone + web.
 *
 * A tall single-scroll detail, vertically centered, pushed the Radix X above
 * the viewport on phones (couldn't close). Tabs + max-height keep title / tabs /
 * Close always on screen; only the active panel scrolls if needed.
 */

import { useEffect, useState, type ReactNode } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Mail,
  Phone,
  Link2,
  AtSign,
  Edit,
  Trash2,
  ShieldOff,
  ShieldCheck,
  HeartCrack,
  ChevronDown,
} from 'lucide-react';
import { ContactReachActions } from '@/components/contacts/ContactReachActions';
import { ContactMethodLink } from '@/components/contacts/ContactMethodLink';
import {
  safeEmailLink,
  safePhoneLink,
  safeUrlLink,
  safeHandleLink,
} from '@/lib/contacts/safe-contact-link';
import { isSvrnNetworkContact } from '@/lib/contacts/is-svrn-contact';
import { solarEmber as E } from '@/components/recovery/solar-ember';

export type ContactDetailModel = {
  id: string;
  name: string;
  email: string;
  fingerprint: string;
  public_key?: string;
  trust_level?: string;
  added_at: string;
  verified_at?: string;
  blocked?: boolean;
  metadata?: {
    notes?: string;
    tags?: string[];
  };
  contact_info?: {
    phones?: string[];
    emails?: string[];
    urls?: string[];
    handles?: Record<string, string>;
  };
};

export type ContactDetailDialogProps = {
  open: boolean;
  contact: ContactDetailModel | null;
  onClose: () => void;
  trustBadge: ReactNode;
  trustIcon: ReactNode;
  isTrusted: boolean;
  isBlocked: boolean;
  onTrustToggle: () => void;
  onEdit: () => void;
  onGivePiece: () => void;
  onBlockToggle: () => void;
  onRemove: () => void;
  onInvite: () => void;
};

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <h4
      style={{
        margin: 0,
        fontSize: 10,
        fontWeight: 600,
        letterSpacing: '0.12em',
        textTransform: 'uppercase',
        color: E.dim,
        fontFamily: E.fontSans,
      }}
    >
      {children}
    </h4>
  );
}

function MethodRow({ icon, children }: { icon: ReactNode; children: ReactNode }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0, fontSize: 13 }}>
      <span style={{ color: E.dim, flexShrink: 0, display: 'inline-flex' }}>{icon}</span>
      <span style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}>{children}</span>
    </div>
  );
}

export function ContactDetailDialog({
  open,
  contact,
  onClose,
  trustBadge,
  trustIcon,
  isTrusted,
  isBlocked,
  onTrustToggle,
  onEdit,
  onGivePiece,
  onBlockToggle,
  onRemove,
  onInvite,
}: ContactDetailDialogProps) {
  const [tab, setTab] = useState('reach');

  useEffect(() => {
    if (open) setTab('reach');
  }, [open, contact?.id]);

  const svrn = contact ? isSvrnNetworkContact(contact) : false;
  const tags = contact?.metadata?.tags || [];
  const extraEmails = (contact?.contact_info?.emails || []).filter(Boolean);
  const phones = (contact?.contact_info?.phones || []).filter(Boolean);
  const urls = (contact?.contact_info?.urls || []).filter(Boolean);
  const handles = contact?.contact_info?.handles || {};

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <DialogContent
        // Clamp height so vertical centering never pushes the X off a phone screen.
        // Explicit Close footer is the primary exit; the Radix X stays in the safe corner.
        className="gap-0 overflow-hidden p-0 sm:rounded-2xl [&>button]:z-20"
        style={{
          width: 'min(28rem, calc(100vw - 1rem))',
          maxWidth: 'calc(100vw - 1rem)',
          maxHeight: 'min(92dvh, 40rem)',
          display: 'flex',
          flexDirection: 'column',
          background: E.surfaceSolid,
          border: `1px solid ${E.border}`,
          color: E.text,
          fontFamily: E.fontSans,
        }}
      >
        {contact ? (
          <>
            <DialogHeader
              className="shrink-0 space-y-1 px-4 pb-2 pt-4 pr-12 text-left"
              style={{ borderBottom: `1px solid ${E.border}` }}
            >
              <DialogTitle
                className="flex items-center gap-2"
                style={{ color: E.text, fontFamily: E.fontSans }}
              >
                <span
                  className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full"
                  style={{
                    background: isTrusted
                      ? 'color-mix(in srgb, var(--se-accent) 18%, transparent)'
                      : 'color-mix(in srgb, var(--se-dim) 18%, transparent)',
                  }}
                >
                  {trustIcon}
                </span>
                <span
                  style={{
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    fontSize: 17,
                  }}
                >
                  {contact.name || 'Unnamed'}
                </span>
              </DialogTitle>
              <DialogDescription
                className="flex flex-wrap items-center gap-2"
                style={{ color: E.muted }}
              >
                {trustBadge}
                <span
                  style={{
                    fontSize: 10,
                    letterSpacing: '0.08em',
                    textTransform: 'uppercase',
                    color: svrn ? E.accent : E.dim,
                  }}
                >
                  {svrn ? 'SVRNTY' : 'Classical'}
                </span>
              </DialogDescription>
            </DialogHeader>

            <Tabs value={tab} onValueChange={setTab} className="flex min-h-0 flex-1 flex-col">
              <TabsList
                className="mx-4 mt-3 grid h-9 w-auto shrink-0 grid-cols-2"
                style={{
                  background: E.inputBg,
                  border: `1px solid ${E.border}`,
                  fontFamily: E.fontSans,
                }}
              >
                <TabsTrigger value="reach" style={{ fontFamily: E.fontSans, fontSize: 12 }}>
                  Reach
                </TabsTrigger>
                <TabsTrigger value="card" style={{ fontFamily: E.fontSans, fontSize: 12 }}>
                  Card
                </TabsTrigger>
              </TabsList>

              <TabsContent
                value="reach"
                className="mt-0 min-h-0 flex-1 overflow-y-auto px-4 py-3 data-[state=inactive]:hidden"
                forceMount
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  <ContactReachActions
                    info={{
                      email: contact.email,
                      phones: contact.contact_info?.phones || [],
                      handles: contact.contact_info?.handles || {},
                    }}
                  />
                  {!svrn ? (
                    <div
                      style={{
                        borderRadius: 12,
                        border: `1px solid ${E.border}`,
                        padding: 12,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 8,
                      }}
                    >
                      <p style={{ margin: 0, fontSize: 12, color: E.muted, lineHeight: 1.45 }}>
                        Classical contact — invite them onto SVRNTY with a link or QR.
                      </p>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={onInvite}
                        style={{ alignSelf: 'flex-start' }}
                      >
                        Invite to SVRNTY
                      </Button>
                    </div>
                  ) : null}
                  {tags.length > 0 ? (
                    <div>
                      <SectionLabel>Groups</SectionLabel>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
                        {tags.map((tag) => (
                          <span
                            key={tag}
                            style={{
                              fontSize: 11,
                              color: E.muted,
                              border: `1px solid ${E.border}`,
                              borderRadius: 6,
                              padding: '2px 8px',
                            }}
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              </TabsContent>

              <TabsContent
                value="card"
                className="mt-0 min-h-0 flex-1 overflow-y-auto px-4 py-3 data-[state=inactive]:hidden"
                forceMount
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  <div>
                    <SectionLabel>Email</SectionLabel>
                    <div style={{ marginTop: 6 }}>
                      <MethodRow icon={<Mail className="h-3.5 w-3.5" />}>
                        <ContactMethodLink safe={safeEmailLink(contact.email)} />
                      </MethodRow>
                    </div>
                  </div>
                  {extraEmails.length > 0 ? (
                    <div>
                      <SectionLabel>More email{extraEmails.length > 1 ? 's' : ''}</SectionLabel>
                      <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {extraEmails.map((email, i) => (
                          <MethodRow key={i} icon={<Mail className="h-3.5 w-3.5" />}>
                            <ContactMethodLink safe={safeEmailLink(email)} />
                          </MethodRow>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {phones.length > 0 ? (
                    <div>
                      <SectionLabel>Phone{phones.length > 1 ? 's' : ''}</SectionLabel>
                      <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {phones.map((phone, i) => (
                          <MethodRow key={i} icon={<Phone className="h-3.5 w-3.5" />}>
                            <ContactMethodLink safe={safePhoneLink(phone)} />
                          </MethodRow>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {urls.length > 0 ? (
                    <div>
                      <SectionLabel>Link{urls.length > 1 ? 's' : ''}</SectionLabel>
                      <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {urls.map((url, i) => (
                          <MethodRow key={i} icon={<Link2 className="h-3.5 w-3.5" />}>
                            <ContactMethodLink safe={safeUrlLink(url)} className="truncate" />
                          </MethodRow>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {Object.keys(handles).length > 0 ? (
                    <div>
                      <SectionLabel>Handles</SectionLabel>
                      <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {Object.entries(handles).map(([platform, handle]) => (
                          <MethodRow key={platform} icon={<AtSign className="h-3.5 w-3.5" />}>
                            <span style={{ color: E.dim }}>{platform}: </span>
                            <ContactMethodLink safe={safeHandleLink(platform, handle)} />
                          </MethodRow>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  <div>
                    <SectionLabel>Fingerprint</SectionLabel>
                    <div
                      style={{
                        marginTop: 6,
                        fontFamily: E.fontMono,
                        fontSize: 11,
                        lineHeight: 1.45,
                        padding: '8px 10px',
                        borderRadius: 8,
                        border: `1px solid ${E.border}`,
                        background: E.inputBg,
                        wordBreak: 'break-all',
                      }}
                    >
                      {contact.fingerprint.match(/.{1,4}/g)?.join(' ') || '—'}
                    </div>
                  </div>
                  {contact.metadata?.notes ? (
                    <div>
                      <SectionLabel>Notes</SectionLabel>
                      <p
                        style={{
                          margin: '6px 0 0',
                          fontSize: 13,
                          color: E.muted,
                          whiteSpace: 'pre-wrap',
                          lineHeight: 1.45,
                        }}
                      >
                        {contact.metadata.notes}
                      </p>
                    </div>
                  ) : null}
                  <div style={{ display: 'flex', gap: 16, fontSize: 12, color: E.muted }}>
                    <span>Added {new Date(contact.added_at).toLocaleDateString()}</span>
                    {contact.verified_at ? (
                      <span>Trusted {new Date(contact.verified_at).toLocaleDateString()}</span>
                    ) : null}
                  </div>
                </div>
              </TabsContent>

            </Tabs>

            <div
              className="shrink-0 flex gap-2 px-4 py-3"
              style={{ borderTop: `1px solid ${E.border}` }}
            >
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    type="button"
                    variant="outline"
                    className="flex-1"
                    style={{ fontFamily: E.fontSans }}
                  >
                    Actions
                    <ChevronDown className="ml-2 h-4 w-4 opacity-70" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent
                  align="start"
                  className="w-52"
                  style={{
                    background: E.surfaceSolid,
                    border: `1px solid ${E.border}`,
                    color: E.text,
                    fontFamily: E.fontSans,
                  }}
                >
                  {!isBlocked ? (
                    <DropdownMenuItem
                      onClick={onTrustToggle}
                      style={{ fontFamily: E.fontSans, cursor: 'pointer' }}
                    >
                      {isTrusted ? (
                        <>
                          <ShieldOff className="mr-2 h-4 w-4" /> Untrust
                        </>
                      ) : (
                        <>
                          <ShieldCheck className="mr-2 h-4 w-4" /> Trust
                        </>
                      )}
                    </DropdownMenuItem>
                  ) : null}
                  {svrn ? (
                    <DropdownMenuItem disabled style={{ fontFamily: E.fontSans }}>
                      <Edit className="mr-2 h-4 w-4" /> Edit locked
                    </DropdownMenuItem>
                  ) : (
                    <DropdownMenuItem
                      onClick={onEdit}
                      style={{ fontFamily: E.fontSans, cursor: 'pointer' }}
                    >
                      <Edit className="mr-2 h-4 w-4" /> Edit
                    </DropdownMenuItem>
                  )}
                  <DropdownMenuItem
                    onClick={onGivePiece}
                    style={{ fontFamily: E.fontSans, cursor: 'pointer' }}
                  >
                    <HeartCrack className="mr-2 h-4 w-4" /> Give a piece
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    onClick={onBlockToggle}
                    style={{ fontFamily: E.fontSans, cursor: 'pointer' }}
                  >
                    {isBlocked ? 'Unblock' : 'Block'}
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={onRemove}
                    className="text-red-400 focus:text-red-300"
                    style={{ fontFamily: E.fontSans, cursor: 'pointer' }}
                  >
                    <Trash2 className="mr-2 h-4 w-4" /> Remove
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
              <Button
                type="button"
                variant="outline"
                className="flex-1"
                onClick={onClose}
                style={{ fontFamily: E.fontSans }}
              >
                Close
              </Button>
            </div>
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
