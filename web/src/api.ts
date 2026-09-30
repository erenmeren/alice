export interface VersionInfo {
  version: string;
  commit: string;
  build_time: string;
}

export async function fetchVersion(): Promise<VersionInfo> {
  const res = await fetch('/api/v1/version', { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`version request failed with status ${res.status}`);
  return (await res.json()) as VersionInfo;
}
