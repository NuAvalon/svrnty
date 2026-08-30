'use client';

/**
 * Compact contact card — phone + web.
 *
 * Classical: edit methods, invite / link → SVRNTY (no trust).
 * SVRNTY: trust / untrust, groups, share toggles; profile edit locked.
 * Pending SVRNTY = they haven't added you yet (no pulse).
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
  Link as LinkIcon,
  Eye,
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
import { IdentitySeal } from '@/components/identity/IdentitySeal';
import {
  defaultShareSettings,
  isPendingSvrntyContact,
  readClassicalExtras,
  readShareSettings,
  type ContactShareSettings,
  type ClassicalExtras,
} from '@/lib/contacts/contact-lane';

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
  connection_status?: string;
  metadata?: {
    notes?: string;
    tags?: string[];
    connection_status?: string;
    pending?: boolean;
    share_settings?: Partial<ContactShareSettings>;
    classical_extras?: ClassicalExtras;
  };
  contact_info?: {
    phones?: string[];
    emails?: string[];
    urls?: string[];
    handles?: Record<string, string>;
  };
  /** Fleet PSI may populate later — glass never invents peer↔peer from tags. */
  peer_mutual?: Array<{ peer_name: string; peer_fingerprint: string }>;
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
  onLinkToSvrnty?: () => void;
  availableGroups?: string[];
  onToggleGroup?: (tag: string) => void;
  onShareSettingsChange?: (next: ContactShareSettings) => void;
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
  onLinkToSvrnty,
  availableGroups = [],
  onToggleGroup,
  onShareSettingsChange,
}: ContactDetailDialogProps) {
  const [tab, setTab] = useState('reach');

  useEffect(() => {
    if (open) setTab('reach');
  }, [open, contact?.id]);

  const svrn = contact ? isSvrnNetworkContact(contact) : false;
  const pending = contact ? isPendingSvrntyContact(contact) : false;
  const tags = contact?.metadata?.tags || [];
  const extraEmails = (contact?.contact_info?.emails || []).filter(Boolean);
  const phones = (contact?.contact_info?.phones || []).filter(Boolean);
  const urls = (contact?.contact_info?.urls || []).filter(Boolean);
  const handles = contact?.contact_info?.handles || {};
  const classicalExtras = contact ? readClassicalExtras(contact) : null;
  const share = contact ? readShareSettings(contact) : defaultShareSettings();
  const groupChoices = Array.from(new Set([...availableGroups, ...tags])).sort();

  const patchShare = (patch: Partial<ContactShareSettings>) => {
    if (!onShareSettingsChange) return;
    onShareSettingsChange({ ...share, ...patch });
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <DialogContent
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
                {svrn && contact.fingerprint ? (
                  <IdentitySeal fingerprint={contact.fingerprint} size={32} />
                ) : (
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
                )}
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
                {svrn ? (
                  trustBadge
                ) : (
                  <span style={{ fontSize: 11, color: E.dim }}>Classical address</span>
                )}
                <span
                  style={{
                    fontSize: 10,
                    letterSpacing: '0.08em',
                    textTransform: 'uppercase',
                    color: svrn ? E.accent : E.dim,
                  }}
                >
                  {svrn ? (pending ? 'SVRNTY · Pending' : 'SVRNTY') : 'Classical'}
                </span>
              </DialogDescription>
            </DialogHeader>

            {pending ? (
              <div
                data-testid="contact-pending-banner"
                style={{
                  margin: '10px 16px 0',
                  padding: '10px 12px',
                  borderRadius: 10,
                  border: `1px dashed ${E.borderLit}`,
                  background: 'color-mix(in srgb, var(--se-accent) 8%, transparent)',
                  fontSize: 12,
                  lineHeight: 1.45,
                  color: E.muted,
                }}
              >
                Pending — they haven&apos;t added you yet. No pulse until the connection is
                mutual. Classical extras stay on the card as additional information.
              </div>
            ) : null}

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
                        Classical contact — edit their numbers here, or link them onto SVRNTY
                        when you have their living card. Trust lives only on SVRNTY.
                      </p>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={onInvite}
                          style={{ alignSelf: 'flex-start' }}
                        >
                          Invite to SVRNTY
                        </Button>
                        {onLinkToSvrnty ? (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={onLinkToSvrnty}
                            data-testid="contact-link-svrnty"
                            style={{ alignSelf: 'flex-start' }}
                          >
                            <LinkIcon className="mr-1.5 h-3.5 w-3.5" />
                            Link to SVRNTY
                          </Button>
                        ) : null}
                      </div>
                    </div>
                  ) : null}

                  {svrn && onShareSettingsChange ? (
                    <div
                      data-testid="contact-share-settings"
                      style={{
                        borderRadius: 12,
                        border: `1px solid ${E.border}`,
                        padding: 12,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 8,
                      }}
                    >
                      <SectionLabel>What you share</SectionLabel>
                      <p style={{ margin: 0, fontSize: 11, color: E.dim, lineHeight: 1.4 }}>
                        Local intent for this peer. When you both trust each other and
                        open visibility, they can see you trust them — and you can see
                        they trust others who also opted in. Disclosure-reach / PSI
                        stay with the fleet; these toggles never invent a bond.
                      </p>
                      {(
                        [
                          ['share_card', 'Show them my card'],
                          ['share_trusted_circle', 'Share trusted-circle membership'],
                          ['share_groups', 'Share overlapping groups I name'],
                          ['open_visibility', 'Open visibility for trusted contacts'],
                        ] as const
                      ).map(([key, label]) => (
                        <label
                          key={key}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 8,
                            fontSize: 12,
                            color: E.muted,
                            cursor: 'pointer',
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={!!share[key]}
                            onChange={(e) => patchShare({ [key]: e.target.checked })}
                          />
                          {label}
                        </label>
                      ))}
                    </div>
                  ) : null}

                  {svrn && contact.peer_mutual && contact.peer_mutual.length > 0 ? (
                    <div>
                      <SectionLabel>Mutual among people you trust</SectionLabel>
                      <p style={{ margin: '6px 0 8px', fontSize: 11, color: E.dim }}>
                        Witnessed via PSI when visibility is open — not inferred.
                      </p>
                      <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: E.muted }}>
                        {contact.peer_mutual.map((m) => (
                          <li key={m.peer_fingerprint}>{m.peer_name}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}

                  <div>
                    <SectionLabel>Groups</SectionLabel>
                    {onToggleGroup && groupChoices.length > 0 ? (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
                        {groupChoices.map((tag) => {
                          const on = tags.includes(tag);
                          return (
                            <button
                              key={tag}
                              type="button"
                              onClick={() => onToggleGroup(tag)}
                              style={{
                                fontSize: 11,
                                color: on ? E.accent : E.muted,
                                border: `1px solid ${on ? E.borderLit : E.border}`,
                                borderRadius: 6,
                                padding: '2px 8px',
                                background: on
                                  ? 'color-mix(in srgb, var(--se-accent) 12%, transparent)'
                                  : 'transparent',
                                cursor: 'pointer',
                                fontFamily: E.fontSans,
                              }}
                            >
                              {tag}
                            </button>
                          );
                        })}
                      </div>
                    ) : tags.length > 0 ? (
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
                    ) : (
                      <p style={{ margin: '8px 0 0', fontSize: 12, color: E.dim }}>
                        No groups yet — assign from the book or Social Graph.
                      </p>
                    )}
                  </div>
                </div>
              </TabsContent>

              <TabsContent
                value="card"
                className="mt-0 min-h-0 flex-1 overflow-y-auto px-4 py-3 data-[state=inactive]:hidden"
                forceMount
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {svrn ? (
                    <p style={{ margin: 0, fontSize: 11, color: E.dim, lineHeight: 1.4 }}>
                      SVRNTY profile is key-bound — edit is locked. Change trust, visibility,
                      and groups from Actions / Reach.
                    </p>
                  ) : null}

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

                  {classicalExtras ? (
                    <div
                      data-testid="classical-extras"
                      style={{
                        marginTop: 4,
                        paddingTop: 12,
                        borderTop: `1px dashed ${E.border}`,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 8,
                      }}
                    >
                      <SectionLabel>Additional information (from classical)</SectionLabel>
                      {classicalExtras.email && classicalExtras.email !== contact.email ? (
                        <MethodRow icon={<Mail className="h-3.5 w-3.5" />}>
                          <ContactMethodLink safe={safeEmailLink(classicalExtras.email)} />
                        </MethodRow>
                      ) : null}
                      {(classicalExtras.phones || []).map((phone, i) => (
                        <MethodRow key={`cx-p-${i}`} icon={<Phone className="h-3.5 w-3.5" />}>
                          <ContactMethodLink safe={safePhoneLink(phone)} />
                        </MethodRow>
                      ))}
                      {(classicalExtras.urls || []).map((url, i) => (
                        <MethodRow key={`cx-u-${i}`} icon={<Link2 className="h-3.5 w-3.5" />}>
                          <ContactMethodLink safe={safeUrlLink(url)} className="truncate" />
                        </MethodRow>
                      ))}
                      {classicalExtras.notes ? (
                        <p style={{ margin: 0, fontSize: 12, color: E.muted, whiteSpace: 'pre-wrap' }}>
                          {classicalExtras.notes}
                        </p>
                      ) : null}
                    </div>
                  ) : null}

                  <div>
                    <SectionLabel>{svrn ? 'Fingerprint' : 'Living key'}</SectionLabel>
                    {svrn && contact.fingerprint ? (
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
                        {contact.fingerprint.match(/.{1,4}/g)?.join(' ')}
                      </div>
                    ) : (
                      <p style={{ margin: '6px 0 0', fontSize: 12, color: E.muted, lineHeight: 1.45 }}>
                        Classical book — no fingerprint. A fingerprint exists only with a living key
                        (invite or link this person to SVRNTY).
                      </p>
                    )}
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
                  {svrn && !isBlocked ? (
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
                  {!svrn ? (
                    <DropdownMenuItem disabled style={{ fontFamily: E.fontSans }}>
                      <Eye className="mr-2 h-4 w-4" /> Trust is SVRNTY-only
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
                      <Edit className="mr-2 h-4 w-4" /> Edit methods
                    </DropdownMenuItem>
                  )}
                  {svrn ? (
                    <DropdownMenuItem
                      onClick={onGivePiece}
                      style={{ fontFamily: E.fontSans, cursor: 'pointer' }}
                    >
                      <HeartCrack className="mr-2 h-4 w-4" /> Give a piece
                    </DropdownMenuItem>
                  ) : null}
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
