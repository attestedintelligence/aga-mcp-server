import { describe, expect, it } from 'vitest';
import { SepGateway, signerFromSeed, verifySepBundle } from '../../src/sep/index.js';

describe('ledger owns its signed receipts', () => {
  it.each(['record', 'getReceipts', 'exportBundle'] as const)('%s does not expose mutable ledger objects', surface => {
    const signer = signerFromSeed(new Uint8Array(32).fill(71));
    const gateway = new SepGateway({ gatewayId: 'synthetic-ownership', signer });
    const returned = gateway.record({ tool_name: 'read', decision: 'PERMITTED', reason: 'original' });
    const exposed = surface === 'record' ? returned : surface === 'getReceipts' ? gateway.getReceipts()[0] : gateway.exportBundle().receipts[0];
    exposed.reason = 'caller mutation';
    gateway.record({ tool_name: 'read', decision: 'DENIED', reason: 'second' });
    const exported = gateway.exportBundle();
    expect(exported.receipts[0].reason).toBe('original');
    expect(verifySepBundle(exported, signer.publicKeyHex).verdict).toBe('VERIFIED');
    expect(verifySepBundle(exported, signer.publicKeyHex).issuerVerified).toBe(true);
  });
});
