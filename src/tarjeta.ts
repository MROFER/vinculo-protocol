// Tarjeta de contacto: lo que dos personas intercambian en persona (por ejemplo, con un código QR).
// Va firmada por la persona, así nadie puede alterar el buzón ni el nombre en el camino.
import type { Billetera } from './billetera.ts';
import { publicaEd25519 } from './cripto/claves.ts';
import { claveDeFirma } from './did/documento.ts';
import type { Resolutor } from './did/resolutor.ts';
import { ahoraEnSegundos, decodificarJws, verificarJws } from './jose.ts';

export const TIPO_TARJETA = 'vinculo-tarjeta+jws';

export interface Tarjeta {
  did: string;
  nombre: string;
  buzon: string;
  iat: number;
  /** Vinculación de nivel A con el documento de identidad, opcional. */
  vinculacion?: string;
}

export function crearTarjeta(billetera: Billetera, datos: Omit<Tarjeta, 'did' | 'iat'>, ahora = ahoraEnSegundos()): string {
  return billetera.firmar({ typ: TIPO_TARJETA }, { ...datos, did: billetera.did, iat: ahora });
}

export async function leerTarjeta(jws: string, resolutor: Resolutor): Promise<Tarjeta> {
  const { cabecera, carga } = decodificarJws<Tarjeta>(jws);
  if (cabecera.typ !== TIPO_TARJETA) throw new Error('no es una tarjeta Vínculo');
  if (!cabecera.kid?.startsWith(`${carga.did}#`)) throw new Error('la tarjeta no está firmada por su titular');
  const documento = await resolutor.resolver(carga.did);
  verificarJws(jws, publicaEd25519(claveDeFirma(documento, cabecera.kid, 'assertionMethod')));
  if (typeof carga.buzon !== 'string' || !/^https?:\/\//.test(carga.buzon)) throw new Error('buzón inválido en la tarjeta');
  return carga;
}
