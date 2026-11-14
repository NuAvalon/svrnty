// The "svrnty isn't live yet" notice is off unless the server's environment says SVRNTY_NOT_LIVE_BANNER=on.
// app/layout.tsx reads it on every request, so changing it takes a container restart, never a rebuild.
export function showNotLiveBanner(path: string | null, setting: string | undefined): boolean {
  return path === '/' && setting === 'on';
}
