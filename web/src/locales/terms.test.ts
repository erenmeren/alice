import en from './en.json';
import tr from './tr.json';

function flat(o: unknown, prefix = '', out: Record<string, string> = {}): Record<string, string> {
  if (typeof o === 'string') out[prefix] = o;
  else if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) flat(v, prefix ? `${prefix}.${k}` : k, out);
  return out;
}

const E = flat(en);
const T = flat(tr);

// R40: Turkish says "içe aktar…" for import everywhere; the only exception is the fixed action label.
describe('Turkish terminology', () => {
  it('says "içe aktar" wherever the English says import, except the fixed action label', () => {
    const bad = Object.entries(E)
      .filter(([k, v]) => /import/i.test(v) && k in T && T[k] !== "Key Vault'a aktar")
      .filter(([k]) => /aktar/i.test(T[k].replace(/[İi]çe aktar/g, '').replace(/dışa aktar/gi, '')))
      .map(([k]) => `${k}: ${T[k]}`);
    expect(bad).toEqual([]);
  });

  it('keeps the fixed action label exactly once as the import action', () => {
    expect(T['imports.action']).toBe("Key Vault'a aktar");
    expect(Object.entries(T).filter(([k, v]) => v === "Key Vault'a aktar" && k !== 'imports.action')).toEqual([]);
  });

  it('says "bekletil" for held, never "tutul", as the catalogue, the audit labels and Phase 4 do', () => {
    // (locations.unsupported.* says "tutuluyor" about a key kept in a hardware module: another meaning.)
    expect(Object.entries(T).filter(([k, v]) => /^(vaults|bindings|imports)\./.test(k) && /tutul/i.test(v)).map(([k, v]) => `${k}: ${v}`)).toEqual([]);
  });

  it('names the Key Vault read step as a verbal noun like its siblings', () => {
    expect(T['deployments.steps.kv_secret']).toBe("Sertifikayı Key Vault'tan okuma");
  });
});

describe('vault texts do not send people to a server', () => {
  it('has no "server\'s page" in the vault, import and binding texts, in either language', () => {
    const vaultOnly = /^(vaults|imports|bindings)\./;
    const bad = [
      ...Object.entries(E).filter(([k, v]) => vaultOnly.test(k) && /server's page/i.test(v)),
      ...Object.entries(T).filter(([k, v]) => vaultOnly.test(k) && /sunucunun sayfası/i.test(v)),
    ].map(([k, v]) => `${k}: ${v}`);
    expect(bad).toEqual([]);
  });
});

