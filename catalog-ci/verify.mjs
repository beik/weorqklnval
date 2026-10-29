import { createHash, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FILES = ['a-ru.bin', 'a-ua.bin', 'a-mm.bin'];
const MAX_VALIDITY = 90 * 86400 * 1000;
const META = ['product', 'platform', 'market_iso', 'config_version', 'inventory_revision', 'issued_at', 'expires_at'];
const fail = reason => { throw new Error(reason); };
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}

export function decode(bytes, market, keys, now = Date.now(), { historical = false } = {}) {
  if (bytes.length < 16 || bytes.subarray(0, 4).toString('ascii') !== 'ZPN1' || bytes.readUInt16BE(4) !== 1) fail('invalid_format');
  const h = bytes.readUInt32BE(6), p = bytes.readUInt32BE(10), s = bytes.readUInt16BE(14);
  if (h < 2 || h > 16384 || p < 2 || p > 4194304 || s < 64 || s > 8192 || bytes.length !== 16 + h + p + s) fail('invalid_lengths');
  let header, payload;
  const payloadBytes = bytes.subarray(16 + h, 16 + h + p), signature = bytes.subarray(16 + h + p);
  try {
    header = JSON.parse(bytes.subarray(16, 16 + h).toString('utf8'));
    payload = JSON.parse(payloadBytes.toString('utf8'));
  } catch { fail('invalid_json'); }
  if (!header || !payload || META.some(k => header[k] !== payload[k])) fail('metadata_mismatch');
  if (payload.product !== 'zeroping' || payload.platform !== 'android' || payload.market_iso !== market) fail('invalid_scope');
  if (typeof payload.config_version !== 'string' || !payload.config_version.trim()) fail('missing_config_version');
  const { inventory_revision: revision, issued_at: issued, expires_at: expires } = payload;
  if (![revision, issued, expires].every(n => Number.isSafeInteger(n) && n > 0)) fail('invalid_metadata');
  if (expires <= issued || expires - issued > MAX_VALIDITY || issued > now + 300000 || (!historical && expires <= now)) fail('invalid_validity');
  if (header.payload_sha256 !== createHash('sha256').update(payloadBytes).digest('hex')) fail('payload_hash_mismatch');
  if (header.signature !== signature.toString('base64url')) fail('signature_field_mismatch');
  const key = Object.hasOwn(keys, header.signature_key_id) && keys[header.signature_key_id];
  if (!key) fail('untrusted_key');
  const unsigned = { ...header }; delete unsigned.signature;
  if (!verify('RSA-SHA256', Buffer.concat([Buffer.from(canonical(unsigned) + '\n'), payloadBytes]), key, signature)) fail('invalid_signature');
  const pool = payload.node_pool;
  if (!pool || !Array.isArray(pool.nodes) || pool.nodes.length === 0 || !Array.isArray(pool.groups) || pool.groups.length === 0) fail('empty_pool');
  const ids = pool.nodes.map(n => String(n?.id || ''));
  if (ids.some(id => !id) || new Set(ids).size !== ids.length) fail('invalid_node_ids');
  if (pool.groups.some(g => !Array.isArray(g.node_ids) || g.node_ids.length === 0 || g.node_ids.some(id => !ids.includes(String(id))))) fail('invalid_groups');
  function inspect(value) {
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
      if (/private|secret|management|token/i.test(key)) fail('forbidden_field');
      inspect(child);
    }
  }
  inspect(payload);
  return { revision, issued, expires, configVersion: payload.config_version, nodes: ids.length, sha256: createHash('sha256').update(bytes).digest('hex') };
}

export function checkPaths(changes) {
  if (!changes.length || changes.some(({status, path}) => !['A', 'M'].includes(status) || !FILES.includes(path))) fail('only_catalog_additions_or_updates_allowed');
}

export function verifySet(readCandidate, readPrevious, keys, now = Date.now()) {
  const results = FILES.map(name => {
    const market = name.slice(2, 4).toUpperCase();
    const result = decode(readCandidate(name), market, keys, now);
    const previous = readPrevious(name);
    if (previous) {
      const old = decode(previous, market, keys, now, { historical: true });
      if (result.revision < old.revision || result.issued < old.issued) fail('catalog_rollback');
    }
    return { file: name, ...result };
  });
  if (new Set(results.map(r => `${r.revision}/${r.issued}/${r.expires}/${r.configVersion}`)).size !== 1) fail('catalog_snapshots_differ');
  return results;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const [base, head] = process.argv.slice(2);
    if (![base, head].every(ref => /^[a-f0-9]{40}$/.test(ref || ''))) fail('commit_sha_required');
    const git = args => execFileSync('git', args, { maxBuffer: 6 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
    // Match the PR's changes; an older branch must not appear to delete newly
    // installed base workflows. Rollback checks still compare with current base.
    const ancestor = git(['merge-base', base, head]).toString('utf8').trim();
    const fields = git(['diff', '--no-renames', '--name-status', '-z', ancestor, head, '--']).toString('utf8').split('\0');
    fields.pop();
    const changes = [];
    for (let i = 0; i < fields.length; i += 2) changes.push({status: fields[i], path: fields[i + 1]});
    checkPaths(changes);
    const keys = JSON.parse(readFileSync(new URL('./trusted-keys.json', import.meta.url), 'utf8'));
    const results = verifySet(name => git(['show', `${head}:${name}`]), name => {
      try { git(['cat-file', '-e', `${base}:${name}`]); } catch { return null; }
      return git(['show', `${base}:${name}`]);
    }, keys);
    console.log(JSON.stringify({result: 'ok', files: results}));
  } catch (error) {
    // Never emit decoded node profiles or Git's raw error output.
    console.error(`Catalog verification failed: ${/^[a-z_]+$/.test(error.message) ? error.message : 'verification_error'}`);
    process.exitCode = 1;
  }
}
