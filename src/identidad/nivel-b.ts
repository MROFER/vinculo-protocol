// Nivel B, credencial del Estado: un emisor confiable entrega a la persona una credencial SD-JWT
// (RFC 9901) ligada a su clave. La persona revela solo los atributos que elige y prueba que la
// credencial es suya con un KB-JWT atado al destinatario y al mensaje.
import { createHash, createPublicKey, randomBytes, type KeyObject, type webcrypto } from 'node:crypto';
import type { Billetera } from '../billetera.ts';
import { aBase64url, deBase64url } from '../codec.ts';
import { generarParEd25519, type ParEd25519 } from '../cripto/claves.ts';
import { ahoraEnSegundos, comprobarVigencia, decodificarJws, firmarJws, verificarJws } from '../jose.ts';

/** Alineado con el borrador SD-JWT VC, que usa la billetera europea. */
export const TIPO_SD_JWT = 'dc+sd-jwt';
export const TIPO_KB_JWT = 'kb+jwt';

type JsonWebKey = webcrypto.JsonWebKey;

const CLAIMS_DE_CONTROL = new Set(['iss', 'iat', 'exp', 'nbf', 'vct', 'cnf', '_sd', '_sd_alg', 'status']);

const resumen = (texto: string) => aBase64url(createHash('sha256').update(texto, 'ascii').digest());

function leerDivulgacion(divulgacion: string): [string, string, unknown] {
  const arreglo = JSON.parse(deBase64url(divulgacion).toString('utf8')) as unknown;
  if (!Array.isArray(arreglo) || arreglo.length !== 3 || typeof arreglo[0] !== 'string' || typeof arreglo[1] !== 'string') {
    throw new Error('divulgación mal formada');
  }
  return arreglo as [string, string, unknown];
}

interface CargaSdJwt {
  iss: string;
  iat: number;
  exp: number;
  vct: string;
  cnf?: { jwk?: JsonWebKey };
  _sd?: string[];
  _sd_alg?: string;
  [claim: string]: unknown;
}

/** Emisor simulado. En producción sería un servicio de AGESIC sobre ID Uruguay (por ejemplo, con OpenID4VCI). */
export class EmisorSimulado {
  readonly id: string;
  #par: ParEd25519;

  constructor(id: string, par: ParEd25519 = generarParEd25519()) {
    this.id = id;
    this.#par = par;
  }

  get clavePublica(): KeyObject {
    return this.#par.publica;
  }

  emitir(
    titular: JsonWebKey,
    atributos: Record<string, unknown>,
    opciones: { vct: string; divulgables: string[]; duracion?: number; ahora?: number },
  ): string {
    const ahora = opciones.ahora ?? ahoraEnSegundos();
    const divulgaciones: string[] = [];
    const resumenes: string[] = [];
    const visibles: Record<string, unknown> = {};
    for (const [nombre, valor] of Object.entries(atributos)) {
      if (!opciones.divulgables.includes(nombre)) {
        visibles[nombre] = valor;
        continue;
      }
      const divulgacion = aBase64url(JSON.stringify([aBase64url(randomBytes(16)), nombre, valor]));
      divulgaciones.push(divulgacion);
      resumenes.push(resumen(divulgacion));
    }
    // Resúmenes señuelo: ocultan cuántos atributos tiene la credencial (RFC 9901, sección 4.2.5).
    for (let i = 0; i < 2; i++) resumenes.push(aBase64url(createHash('sha256').update(randomBytes(32)).digest()));
    resumenes.sort();

    const carga: CargaSdJwt = {
      ...visibles,
      iss: this.id,
      iat: ahora,
      exp: ahora + (opciones.duracion ?? 365 * 24 * 3600),
      vct: opciones.vct,
      cnf: { jwk: { kty: titular.kty, crv: titular.crv, x: titular.x } },
      _sd: resumenes,
      _sd_alg: 'sha-256',
    };
    const jwt = firmarJws({ alg: 'EdDSA', typ: TIPO_SD_JWT, kid: `${this.id}#clave-1` }, carga, this.#par.privada);
    return `${jwt}~${divulgaciones.map((d) => `${d}~`).join('')}`;
  }
}

/** La persona arma una presentación con solo los atributos elegidos y la firma con su billetera. */
export function presentar(
  sdJwt: string,
  revelar: string[],
  billetera: Billetera,
  opciones: { aud: string; nonce: string; ahora?: number },
): string {
  const [jwt, ...resto] = sdJwt.split('~');
  const elegidas = resto.filter((d) => d !== '' && revelar.includes(leerDivulgacion(d)[1]));
  const sinPrueba = `${jwt}~${elegidas.map((d) => `${d}~`).join('')}`;
  const prueba = billetera.firmar(
    { typ: TIPO_KB_JWT },
    { iat: opciones.ahora ?? ahoraEnSegundos(), aud: opciones.aud, nonce: opciones.nonce, sd_hash: resumen(sinPrueba) },
  );
  return sinPrueba + prueba;
}

export interface ResultadoPresentacion {
  emisor: string;
  vct: string;
  atributos: Record<string, unknown>;
}

export function verificarPresentacion(
  presentacion: string,
  opciones: { emisores: ReadonlyMap<string, KeyObject>; aud: string; nonce: string; ahora?: number; ventana?: number },
): ResultadoPresentacion {
  const ahora = opciones.ahora ?? ahoraEnSegundos();
  const partes = presentacion.split('~');
  if (partes.length < 2) throw new Error('presentación SD-JWT mal formada');
  const prueba = partes.pop();
  if (!prueba) throw new Error('falta la prueba de posesión (KB-JWT)');
  const [jwt, ...divulgaciones] = partes;

  // Firma y vigencia del emisor.
  const { cabecera, carga } = decodificarJws<CargaSdJwt>(jwt);
  if (cabecera.typ !== TIPO_SD_JWT) throw new Error('no es una credencial SD-JWT');
  const clave = opciones.emisores.get(carga.iss);
  if (!clave) throw new Error(`emisor no confiable: ${carga.iss}`);
  verificarJws(jwt, clave);
  comprobarVigencia(carga, ahora, 'credencial');
  if ((carga._sd_alg ?? 'sha-256') !== 'sha-256') throw new Error('algoritmo de resumen no soportado');

  // Atributos visibles más los revelados, cada uno respaldado por un resumen que firmó el emisor.
  const atributos: Record<string, unknown> = {};
  for (const [nombre, valor] of Object.entries(carga)) if (!CLAIMS_DE_CONTROL.has(nombre)) atributos[nombre] = valor;
  const firmados = new Set(carga._sd ?? []);
  const usados = new Set<string>();
  for (const divulgacion of divulgaciones) {
    const r = resumen(divulgacion);
    if (!firmados.has(r) || usados.has(r)) throw new Error('un atributo revelado no fue firmado por el emisor');
    usados.add(r);
    const [, nombre, valor] = leerDivulgacion(divulgacion);
    if (nombre === '_sd' || nombre === '...' || CLAIMS_DE_CONTROL.has(nombre) || nombre in atributos) {
      throw new Error(`atributo revelado inválido: ${nombre}`);
    }
    atributos[nombre] = valor;
  }

  // Prueba de posesión: la presenta la persona dueña de la credencial, para este destinatario y este mensaje.
  const jwk = carga.cnf?.jwk;
  if (!jwk) throw new Error('la credencial no está ligada a una clave');
  const kb = verificarJws<{ iat: number; aud: string; nonce: string; sd_hash: string }>(prueba, createPublicKey({ key: jwk, format: 'jwk' }));
  if (kb.cabecera.typ !== TIPO_KB_JWT) throw new Error('prueba de posesión inválida');
  if (kb.carga.aud !== opciones.aud || kb.carga.nonce !== opciones.nonce) throw new Error('la presentación es para otro destinatario o mensaje');
  if (Math.abs(ahora - kb.carga.iat) > (opciones.ventana ?? 300)) throw new Error('la presentación no es reciente');
  if (kb.carga.sd_hash !== resumen(`${partes.join('~')}~`)) throw new Error('la prueba de posesión no corresponde a lo presentado');

  return { emisor: carga.iss, vct: carga.vct, atributos };
}
