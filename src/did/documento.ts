// Documento DID (W3C DID Core) y utilidades para extraer claves y buzones.
import { aBase58btc, deBase58btc } from '../codec.ts';

export interface MetodoVerificacion {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase: string;
}

export interface Servicio {
  id: string;
  type: string;
  serviceEndpoint: string;
}

export interface DocumentoDid {
  '@context'?: unknown;
  id: string;
  verificationMethod?: MetodoVerificacion[];
  authentication?: string[];
  assertionMethod?: string[];
  capabilityDelegation?: string[];
  keyAgreement?: string[];
  service?: Servicio[];
}

export type Relacion = 'authentication' | 'assertionMethod' | 'capabilityDelegation' | 'keyAgreement';

// Prefijos multicodec (varint) de cada tipo de clave.
export const MULTICODEC_ED25519 = Uint8Array.of(0xed, 0x01);
export const MULTICODEC_X25519 = Uint8Array.of(0xec, 0x01);

/** Tipo de servicio con el que una persona publica su buzón. */
export const SERVICIO_BUZON = 'VinculoBuzon';

export function multibaseDeClave(prefijo: Uint8Array, cruda: Uint8Array): string {
  return 'z' + aBase58btc(Uint8Array.from([...prefijo, ...cruda]));
}

export function claveDeMultibase(multibase: string, prefijo: Uint8Array): Uint8Array {
  if (!multibase.startsWith('z')) throw new Error('solo se admite multibase base58btc');
  const bytes = deBase58btc(multibase.slice(1));
  if (bytes.length !== prefijo.length + 32 || bytes[0] !== prefijo[0] || bytes[1] !== prefijo[1]) {
    throw new Error('tipo de clave inesperado');
  }
  return bytes.subarray(prefijo.length);
}

function metodo(doc: DocumentoDid, kid: string): MetodoVerificacion {
  const encontrado = (doc.verificationMethod ?? []).find((m) => m.id === kid);
  if (!encontrado) throw new Error(`método de verificación no encontrado: ${kid}`);
  return encontrado;
}

/** Clave Ed25519 del método `kid`, siempre que el documento la autorice para la relación pedida. */
export function claveDeFirma(doc: DocumentoDid, kid: string, relacion: Exclude<Relacion, 'keyAgreement'>): Uint8Array {
  if (!(doc[relacion] ?? []).includes(kid)) {
    throw new Error(`la clave ${kid} no está autorizada para ${relacion}`);
  }
  return claveDeMultibase(metodo(doc, kid).publicKeyMultibase, MULTICODEC_ED25519);
}

/** Primera clave X25519 de acuerdo de claves: a ella se cifran los sobres dirigidos a esta persona. */
export function claveDeAcuerdo(doc: DocumentoDid): { kid: string; publica: Uint8Array } {
  const kid = doc.keyAgreement?.[0];
  if (!kid) throw new Error(`${doc.id} no publica una clave de acuerdo`);
  return { kid, publica: claveDeMultibase(metodo(doc, kid).publicKeyMultibase, MULTICODEC_X25519) };
}

export function buzonesDe(doc: DocumentoDid): string[] {
  return (doc.service ?? []).filter((s) => s.type === SERVICIO_BUZON).map((s) => s.serviceEndpoint);
}
