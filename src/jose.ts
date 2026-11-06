// JWS compacto (RFC 7515) con EdDSA (RFC 8037) o RS256, sin dependencias externas.
import { sign, verify, type KeyObject } from 'node:crypto';
import { aBase64url, deBase64url } from './codec.ts';

export interface CabeceraJws {
  alg: 'EdDSA' | 'RS256';
  typ?: string;
  kid?: string;
  x5c?: string[];
}

export interface JwsDecodificado<T> {
  cabecera: CabeceraJws;
  carga: T;
  entrada: Buffer;
  firma: Buffer;
}

const hash = (alg: CabeceraJws['alg']) => (alg === 'EdDSA' ? null : 'sha256');

export function ahoraEnSegundos(): number {
  return Math.floor(Date.now() / 1000);
}

export function firmarJws(cabecera: CabeceraJws, carga: unknown, privada: KeyObject): string {
  const entrada = `${aBase64url(JSON.stringify(cabecera))}.${aBase64url(JSON.stringify(carga))}`;
  const firma = sign(hash(cabecera.alg), Buffer.from(entrada, 'ascii'), privada);
  return `${entrada}.${aBase64url(firma)}`;
}

export function decodificarJws<T = Record<string, unknown>>(jws: string): JwsDecodificado<T> {
  const partes = typeof jws === 'string' ? jws.split('.') : [];
  if (partes.length !== 3) throw new Error('JWS mal formado');
  const [cabecera, carga, firma] = partes;
  return {
    cabecera: JSON.parse(deBase64url(cabecera).toString('utf8')) as CabeceraJws,
    carga: JSON.parse(deBase64url(carga).toString('utf8')) as T,
    entrada: Buffer.from(`${cabecera}.${carga}`, 'ascii'),
    firma: deBase64url(firma),
  };
}

export function verificarJws<T = Record<string, unknown>>(
  jws: string,
  publica: KeyObject,
  algEsperado: CabeceraJws['alg'] = 'EdDSA',
): JwsDecodificado<T> {
  const decodificado = decodificarJws<T>(jws);
  if (decodificado.cabecera.alg !== algEsperado) throw new Error(`algoritmo inesperado: ${decodificado.cabecera.alg}`);
  if (!verify(hash(algEsperado), decodificado.entrada, publica, decodificado.firma)) throw new Error('firma inválida');
  return decodificado;
}

/** Comprueba iat, nbf y exp con una tolerancia de reloj en segundos. */
export function comprobarVigencia(
  carga: { iat?: number; nbf?: number; exp?: number },
  ahora: number,
  que: string,
  tolerancia = 60,
): void {
  if (typeof carga.exp === 'number' && ahora > carga.exp + tolerancia) throw new Error(`${que}: venció`);
  if (typeof carga.nbf === 'number' && ahora + tolerancia < carga.nbf) throw new Error(`${que}: aún no entra en vigencia`);
  if (typeof carga.iat === 'number' && ahora + tolerancia < carga.iat) throw new Error(`${que}: fecha de emisión futura`);
}
