import { redirect } from 'next/navigation';

export default async function BareNameRedirect({ params }: { params: Promise<{ name: string }> }) {
  const { name } = await params;
  redirect(`/u/${encodeURIComponent(name)}`);
}
