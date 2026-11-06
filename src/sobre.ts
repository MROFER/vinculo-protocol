// Sobre cifrado: JWE compacto (RFC 7516) con ECDH-ES sobre X25519 (RFC 8037) y A256GCM (RFC 7518).
// El buzón que lo transporta solo ve el destinatario y una cabecera técnica; el remitente va adentro.
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  diffieHellman,
  generateKeyPairSync,
  randomBytes,
  type KeyObject,
} from 'node:crypto';
import { aBase64url, deBase64url } from './codec.ts';
import { crudaDePublica, publicaX25519 } from './cripto/claves.ts';

export const TIPO_SOBRE = 'vinculo-sobre+jwe';
export const TIPO_MENSAJE_FIRMADO = 'vinculo-mensaje+jws';

export interface Destinatario {
  kid: string;
  publica: Uint8Array;
}

export interface CabeceraSobre {
  alg: string;
  enc: string;
  typ?: string;
  cty?: string;
  kid: string;
  epk: { kty: string; crv: string; x: string };
}

/** Concat KDF de NIST SP 800-56A con SHA-256, como lo define RFC 7518 §4.6.2. */
export function concatKdf(
  z: Uint8Array,
  algoritmo: string,
  bits: number,
  apu: Uint8Array = new Uint8Array(),
  apv: Uint8Array = new Uint8Array(),
): Buffer {
  const entero = (n: number) => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    return b;
  };
  const conLargo = (b: Uint8Array) => Buffer.concat([entero(b.length), b]);
  const otraInfo = Buffer.concat([conLargo(Buffer.from(algoritmo, 'ascii')), conLargo(apu), conLargo(apv), entero(bits)]);
  const rondas: Buffer[] = [];
  for (let i = 1; i <= Math.ceil(bits / 256); i++) {
    rondas.push(createHash('sha256').update(entero(i)).update(z).update(otraInfo).digest());
  }
  return Buffer.concat(rondas).subarray(0, bits / 8);
}

export function cifrar(destinatario: Destinatario, contenido: string): string {
  const efimera = generateKeyPairSync('x25519');
  const cabecera: CabeceraSobre = {
    alg: 'ECDH-ES',
    enc: 'A256GCM',
    typ: TIPO_SOBRE,
    cty: TIPO_MENSAJE_FIRMADO,
    kid: destinatario.kid,
    epk: { kty: 'OKP', crv: 'X25519', x: aBase64url(crudaDePublica(efimera.publicKey)) },
  };
  const cabeceraB64 = aBase64url(JSON.stringify(cabecera));
  const z = diffieHellman({ privateKey: efimera.privateKey, publicKey: publicaX25519(destinatario.publica) });
  const iv = randomBytes(12);
  const cifrador = createCipheriv('aes-256-gcm', concatKdf(z, 'A256GCM', 256), iv);
  cifrador.setAAD(Buffer.from(cabeceraB64, 'ascii'));
  const texto = Buffer.concat([cifrador.update(contenido, 'utf8'), cifrador.final()]);
  return [cabeceraB64, '', aBase64url(iv), aBase64url(texto), aBase64url(cifrador.getAuthTag())].join('.');
}

export function leerCabeceraSobre(jwe: string): CabeceraSobre {
  const partes = jwe.split('.');
  if (partes.length !== 5) throw new Error('sobre mal formado');
  return JSON.parse(deBase64url(partes[0]).toString('utf8')) as CabeceraSobre;
}

export function descifrar(privada: KeyObject, kidPropio: string, jwe: string): string {
  const partes = jwe.split('.');
  if (partes.length !== 5) throw new Error('sobre mal formado');
  const [cabeceraB64, claveCifrada, ivB64, textoB64, etiquetaB64] = partes;
  const cabecera = leerCabeceraSobre(jwe);
  if (cabecera.alg !== 'ECDH-ES' || cabecera.enc !== 'A256GCM') throw new Error('algoritmo de sobre no soportado');
  if (claveCifrada !== '') throw new Error('ECDH-ES directo no lleva clave cifrada');
  if (cabecera.kid !== kidPropio) throw new Error('el sobre no está dirigido a esta persona');
  if (cabecera.epk?.kty !== 'OKP' || cabecera.epk.crv !== 'X25519') throw new Error('clave efímera inválida');

  const z = diffieHellman({ privateKey: privada, publicKey: publicaX25519(deBase64url(cabecera.epk.x)) });
  const iv = deBase64url(ivB64);
  const etiqueta = deBase64url(etiquetaB64);
  if (iv.length !== 12 || etiqueta.length !== 16) throw new Error('sobre mal formado');
  const descifrador = createDecipheriv('aes-256-gcm', concatKdf(z, 'A256GCM', 256), iv);
  descifrador.setAAD(Buffer.from(cabeceraB64, 'ascii'));
  descifrador.setAuthTag(etiqueta);
  try {
    return Buffer.concat([descifrador.update(deBase64url(textoB64)), descifrador.final()]).toString('utf8');
  } catch {
    throw new Error('el sobre fue alterado o la clave no corresponde');
  }
}
