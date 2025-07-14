import { IdentityCreationTester } from '@/components/IdentityCreationTester';

export default function DebugPage() {
  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">Debug Tools</h1>
      <IdentityCreationTester />
    </div>
  );
}