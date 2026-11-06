// Delegación: la persona autoriza a un agente, que tiene su propia clave, a actuar en su nombre
// con un alcance limitado y un vencimiento. La persona puede revocarla en cualquier momento.
import { publicaEd25519 } from './cripto/claves.ts';
import { claveDeFirma } from './did/documento.ts';
import type { Resolutor } from './did/resolutor.ts';
import { comprobarVigencia, decodificarJws, verificarJws } from './jose.ts';

export const TIPO_DELEGACION = 'vinculo-delegacion+jwt';
export const TIPO_REVOCACIONES = 'vinculo-revocaciones+jwt';

/** Permisos que no son tipos de mensaje. */
export const ALCANCE = {
  leerBuzon: 'buzon:leer',
  descifrar: 'billetera:descifrar',
} as const;

/** Dónde procesa el agente el contenido descifrado. Quien recibe puede exigir un nivel. */
export type Procesamiento = 'local' | 'enclave' | 'nube';

export interface DatosAgente {
  nombre: string;
  proveedor: string;
  procesamiento: Procesamiento;
}

// El nombre del agente y el de su proveedor los ve la otra persona, y también su asistente de IA. Por eso no
// admiten saltos de línea, comillas, paréntesis ni otros signos con los que se pueda imitar el formato de un
// mensaje: solo letras, números, espacios y «. _ & ' + -», hasta 40 caracteres (SPEC, sección 4.1).
const CARACTER_DE_NOMBRE = String.raw`[\p{L}\p{N} ._&'+-]`;
const NOMBRE_DE_AGENTE = new RegExp(String.raw`^[\p{L}\p{N}]${CARACTER_DE_NOMBRE}{0,39}$`, 'u');
const PROCESAMIENTOS: readonly string[] = ['local', 'enclave', 'nube'] satisfies Procesamiento[];

/** Exige que los datos del agente cumplan la sección 4.1. No repite el valor recibido en el error. */
export function validarDatosAgente(datos: unknown): asserts datos is DatosAgente {
  if (typeof datos !== 'object' || datos === null) throw new Error('la delegación no describe al agente');
  const d = datos as Record<string, unknown>;
  for (const campo of ['nombre', 'proveedor']) {
    const valor = d[campo];
    if (typeof valor !== 'string' || !NOMBRE_DE_AGENTE.test(valor)) throw new Error(`el ${campo} del agente no es válido`);
  }
  if (typeof d.procesamiento !== 'string' || !PROCESAMIENTOS.includes(d.procesamiento)) {
    throw new Error('el procesamiento del agente no es válido');
  }
}

/** Lleva un nombre cualquiera (por ejemplo, el que declara un cliente MCP) a la forma que admite una delegación. */
export function limpiarNombreDeAgente(texto: string, porDefecto = 'Asistente'): string {
  const limpio = texto
    .normalize('NFC')
    .replace(new RegExp(String.raw`(?!${CARACTER_DE_NOMBRE}).`, 'gsu'), ' ')
    .replace(/^[^\p{L}\p{N}]+/u, '')
    .replace(/\s+/g, ' ')
    .slice(0, 40)
    .trim();
  return NOMBRE_DE_AGENTE.test(limpio) ? limpio : porDefecto;
}

export interface Delegacion {
  iss: string;
  sub: string;
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
  alcance: string[];
  agente: DatosAgente;
}

export interface ListaRevocaciones {
  iss: string;
  iat: number;
  version: number;
  revocadas: string[];
}

export interface RequisitosDelegacion {
  ahora: number;
  /** DID de la persona que tuvo que delegar. */
  emisor?: string;
  /** DID del agente que tiene que ser el sujeto. */
  agente?: string;
  alcance?: string;
  revocadas?: ReadonlySet<string>;
}

export async function verificarDelegacion(
  jwt: string,
  resolutor: Resolutor,
  requisitos: RequisitosDelegacion,
): Promise<Delegacion> {
  const { cabecera, carga } = decodificarJws<Delegacion>(jwt);
  if (cabecera.typ !== TIPO_DELEGACION) throw new Error('no es una delegación Vínculo');
  if (!cabecera.kid?.startsWith(`${carga.iss}#`)) throw new Error('la delegación no está firmada por quien la emite');
  const documento = await resolutor.resolver(carga.iss);
  verificarJws(jwt, publicaEd25519(claveDeFirma(documento, cabecera.kid, 'capabilityDelegation')));
  comprobarVigencia(carga, requisitos.ahora, 'delegación');
  if (requisitos.emisor && carga.iss !== requisitos.emisor) throw new Error('la delegación es de otra persona');
  if (requisitos.agente && carga.sub !== requisitos.agente) throw new Error('la delegación es para otro agente');
  if (!Array.isArray(carga.alcance)) throw new Error('delegación sin alcance');
  validarDatosAgente(carga.agente);
  if (requisitos.alcance && !carga.alcance.includes(requisitos.alcance)) {
    throw new Error(`la delegación no incluye «${requisitos.alcance}»`);
  }
  if (requisitos.revocadas?.has(carga.jti)) throw new Error('delegación revocada por su titular');
  return carga;
}

export async function verificarRevocaciones(jwt: string, resolutor: Resolutor, persona: string): Promise<ListaRevocaciones> {
  const { cabecera, carga } = decodificarJws<ListaRevocaciones>(jwt);
  if (cabecera.typ !== TIPO_REVOCACIONES) throw new Error('no es una lista de revocaciones');
  if (carga.iss !== persona || !cabecera.kid?.startsWith(`${persona}#`)) throw new Error('la lista de revocaciones es de otra persona');
  const documento = await resolutor.resolver(persona);
  verificarJws(jwt, publicaEd25519(claveDeFirma(documento, cabecera.kid, 'assertionMethod')));
  if (!Array.isArray(carga.revocadas) || !Number.isInteger(carga.version)) throw new Error('lista de revocaciones mal formada');
  return carga;
}
