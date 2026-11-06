// Claves Ed25519 (firma) y X25519 (acuerdo de claves), y la conversión de una a otra.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';

// Prefijos DER de PKCS#8 y SPKI para claves de 32 bytes (RFC 8410).
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8_X25519 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const SPKI_X25519 = Buffer.from('302a300506032b656e032100', 'hex');

export interface ParEd25519 {
  privada: KeyObject;
  publica: KeyObject;
  /** Los 32 bytes de la clave pública. */
  publicaCruda: Uint8Array;
}

export function generarParEd25519(): ParEd25519 {
  return parDesdePrivada(generateKeyPairSync('ed25519').privateKey);
}

export function parEd25519DesdeSemilla(semilla: Uint8Array): ParEd25519 {
  if (semilla.length !== 32) throw new Error('la semilla Ed25519 debe tener 32 bytes');
  const der = Buffer.concat([PKCS8_ED25519, semilla]);
  return parDesdePrivada(createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }));
}

function parDesdePrivada(privada: KeyObject): ParEd25519 {
  const publica = createPublicKey(privada);
  return { privada, publica, publicaCruda: crudaDePublica(publica) };
}

export function semillaEd25519(privada: KeyObject): Uint8Array {
  const der = privada.export({ format: 'der', type: 'pkcs8' });
  if (der.length !== PKCS8_ED25519.length + 32) throw new Error('formato PKCS#8 inesperado');
  return der.subarray(PKCS8_ED25519.length);
}

/** Los 32 bytes de una clave pública Ed25519 o X25519. */
export function crudaDePublica(publica: KeyObject): Uint8Array {
  const der = publica.export({ format: 'der', type: 'spki' });
  if (der.length !== SPKI_ED25519.length + 32) throw new Error('formato SPKI inesperado');
  return der.subarray(SPKI_ED25519.length);
}

export function publicaEd25519(cruda: Uint8Array): KeyObject {
  if (cruda.length !== 32) throw new Error('clave pública Ed25519 inválida');
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519, cruda]), format: 'der', type: 'spki' });
}

export function publicaX25519(cruda: Uint8Array): KeyObject {
  if (cruda.length !== 32) throw new Error('clave pública X25519 inválida');
  return createPublicKey({ key: Buffer.concat([SPKI_X25519, cruda]), format: 'der', type: 'spki' });
}

export function privadaX25519(cruda: Uint8Array): KeyObject {
  if (cruda.length !== 32) throw new Error('clave privada X25519 inválida');
  return createPrivateKey({ key: Buffer.concat([PKCS8_X25519, cruda]), format: 'der', type: 'pkcs8' });
}

// De Ed25519 a X25519 con el mapa birracional de Edwards a Montgomery, u = (1 + y) / (1 - y) mod p.
// Es la misma conversión que usan libsodium y did:key para derivar la clave de acuerdo.
const P = 2n ** 255n - 19n;

function potenciaModular(base: bigint, exponente: bigint, modulo: bigint): bigint {
  let resultado = 1n;
  base %= modulo;
  while (exponente > 0n) {
    if (exponente & 1n) resultado = (resultado * base) % modulo;
    base = (base * base) % modulo;
    exponente >>= 1n;
  }
  return resultado;
}

export function x25519PublicaDesdeEd25519(publicaEd: Uint8Array): Uint8Array {
  if (publicaEd.length !== 32) throw new Error('clave pública Ed25519 inválida');
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? publicaEd[i] & 0x7f : publicaEd[i]);
  if (y >= P) throw new Error('clave pública Ed25519 inválida');
  const denominador = (1n - y + P) % P;
  if (denominador === 0n) throw new Error('clave pública Ed25519 inválida');
  let u = ((1n + y) * potenciaModular(denominador, P - 2n, P)) % P;
  const salida = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    salida[i] = Number(u & 0xffn);
    u >>= 8n;
  }
  return salida;
}

export function x25519PrivadaDesdeEd25519(semilla: Uint8Array): KeyObject {
  return privadaX25519(createHash('sha512').update(semilla).digest().subarray(0, 32));
}
