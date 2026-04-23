import { generateKeyPair, pkToHex } from '../src/crypto/sign.js';
import { bytesToHex } from '@noble/hashes/utils';

const kp = generateKeyPair();
console.log(JSON.stringify({
  publicKey: pkToHex(kp.publicKey),
  secretKey: bytesToHex(kp.secretKey),
}, null, 2));
