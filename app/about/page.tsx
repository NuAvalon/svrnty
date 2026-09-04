import type { Metadata } from 'next';
import { AboutPage } from '@/components/about/AboutPage';

export const metadata: Metadata = {
  title: 'About — svrnty',
  description:
    'Sovereign identity, living contacts, and a consent-gated trust graph — local-first, on your device.',
};

export default function AboutRoute() {
  return <AboutPage />;
}
