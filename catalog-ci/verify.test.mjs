import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { canonical, checkPaths, decode, FILES, verifySet } from './verify.mjs';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const keys = { test: publicKey };
const now = 1800000000000;
function encode(market, patch = {}, headerPatch = {}) {
  const payload = { product: 'zeroping', platform: 'android', market_iso: market, config_version: 'cfg-test-42', inventory_revision: 42,
    issued_at: now - 1000, expires_at: now + 86400000,
    node_pool: { nodes: [{id: '1001'}], groups: [{node_ids: ['1001']}] }, ...patch };
  const body = Buffer.from(canonical(payload));
  const header = { product: payload.product, platform: payload.platform, market_iso: market, config_version: payload.config_version,
    inventory_revision: payload.inventory_revision, issued_at: payload.issued_at, expires_at: payload.expires_at,
    payload_sha256: createHash('sha256').update(body).digest('hex'), signature_key_id: 'test', ...headerPatch };
  const signature = sign('RSA-SHA256', Buffer.concat([Buffer.from(canonical(header) + '\n'), body]), privateKey);
  const encodedHeader = Buffer.from(canonical({...header, signature: signature.toString('base64url')}));
  const fixed = Buffer.alloc(16); fixed.write('ZPN1'); fixed.writeUInt16BE(1, 4);
  fixed.writeUInt32BE(encodedHeader.length, 6); fixed.writeUInt32BE(body.length, 10); fixed.writeUInt16BE(signature.length, 14);
  return Buffer.concat([fixed, encodedHeader, body, signature]);
}
const candidate = (name, patch) => encode(name.slice(2, 4).toUpperCase(), patch);
test('accepts consistent signed three-market snapshot', () => {
  assert.equal(verifySet(candidate, () => null, keys, now).length, 3);
});
test('rejects modified bytes, unknown key, wrong market and mismatched metadata', () => {
  const modified = encode('RU'); modified[modified.length - 1] ^= 1;
  assert.throws(() => decode(modified, 'RU', keys, now), /signature/);
  assert.throws(() => decode(encode('RU'), 'RU', {}, now), /untrusted_key/);
  assert.throws(() => decode(encode('RU'), 'MM', keys, now), /invalid_scope/);
  assert.throws(() => decode(encode('RU', {}, {inventory_revision: 43}), 'RU', keys, now), /metadata_mismatch/);
});
test('rejects expiry, future issue time and validity longer than 90 days', () => {
  for (const patch of [{expires_at: now - 1}, {issued_at: now + 600000}, {expires_at: now + 91 * 86400000}]) {
    assert.throws(() => decode(encode('RU', patch), 'RU', keys, now), /invalid_validity/);
  }
});
test('rejects rollback and different market revisions or issue times', () => {
  assert.throws(() => verifySet(candidate, name => candidate(name, {inventory_revision: 43}), keys, now), /rollback/);
  assert.throws(() => verifySet(candidate, name => candidate(name, {issued_at: now}), keys, now), /rollback/);
  for (const patch of [{inventory_revision: 43}, {issued_at: now - 2000}, {config_version: 'other'}]) {
    assert.throws(() => verifySet(name => candidate(name, name === 'a-mm.bin' ? patch : {}), () => null, keys, now), /snapshots_differ/);
  }
});
test('expired historical baseline does not block a valid refresh', () => {
  assert.equal(verifySet(candidate, name => candidate(name, {issued_at: now - 90000000, expires_at: now - 1000}), keys, now).length, 3);
});
test('requires every market and rejects empty pools, invalid groups and private fields', () => {
  assert.throws(() => verifySet(name => name === FILES[2] ? Buffer.alloc(0) : candidate(name), () => null, keys, now), /invalid_format/);
  for (const patch of [{node_pool: {nodes: [], groups: []}}, {node_pool: {nodes: [{id: 1}], groups: [{node_ids: [2]}]}}, {private_key: 'test'}]) {
    assert.throws(() => decode(encode('RU', patch), 'RU', keys, now), /empty_pool|invalid_groups|forbidden_field/);
  }
});
test('rejects workflow/code changes, deletions, renames and empty updates', () => {
  checkPaths([{status: 'A', path: 'a-mm.bin'}, {status: 'M', path: 'a-ru.bin'}]);
  for (const changes of [[], [{status: 'M', path: '.github/workflows/verify-node-catalog.yml'}], [{status: 'D', path: 'a-ru.bin'}], [{status: 'R100', path: 'a-ru.bin'}]]) {
    assert.throws(() => checkPaths(changes), /only_catalog/);
  }
});
