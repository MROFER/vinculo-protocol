// Cliente HTTP del buzón: depositar sobres, retirarlos con autorización firmada y publicar revocaciones.
import { randomUUID } from 'node:crypto';
import { ahoraEnSegundos } from '../jose.ts';
import { TIPO_ACCESO, type SobreGuardado } from './servidor.ts';

/** Quien firma las autorizaciones: la persona o un agente con delegación. */
export interface Firmante {
  did: string;
  firmar(cabecera: { typ: string }, carga: Record<string, unknown>): string;
  delegacion?: string;
}

const camino = (...partes: string[]) => '/' + partes.map(encodeURIComponent).join('/');

async function exigir(respuesta: Response, esperado: number, que: string): Promise<void> {
  if (respuesta.status === esperado) return;
  let detalle = '';
  try {
    detalle = ((await respuesta.json()) as { error?: string }).error ?? '';
  } catch {
    // sin cuerpo JSON
  }
  throw new Error(`${que} (${respuesta.status})${detalle ? `: ${detalle}` : ''}`);
}

export async function depositar(buzon: string, destinatario: string, jwe: string): Promise<string> {
  const respuesta = await fetch(buzon + camino('v1', 'buzon', destinatario), {
    method: 'POST',
    headers: { 'content-type': 'application/jose' },
    body: jwe,
  });
  await exigir(respuesta, 202, 'el buzón rechazó el sobre');
  return ((await respuesta.json()) as { id: string }).id;
}

export async function publicarRevocaciones(buzon: string, persona: string, jwt: string): Promise<void> {
  const respuesta = await fetch(buzon + camino('v1', 'estado', persona), {
    method: 'PUT',
    headers: { 'content-type': 'application/jwt' },
    body: jwt,
  });
  await exigir(respuesta, 204, 'el buzón rechazó la lista de revocaciones');
}

export async function obtenerRevocaciones(buzon: string, persona: string): Promise<string | null> {
  const respuesta = await fetch(buzon + camino('v1', 'estado', persona));
  if (respuesta.status === 404) return null;
  await exigir(respuesta, 200, 'no se pudo leer la lista de revocaciones');
  return ((await respuesta.json()) as { revocaciones: string }).revocaciones;
}

export class ClienteBuzon {
  #base: string;
  #persona: string;
  #firmante: Firmante;

  constructor(base: string, persona: string, firmante: Firmante) {
    this.#base = base;
    this.#persona = persona;
    this.#firmante = firmante;
  }

  #autorizacion(metodo: string, ruta: string): string {
    const carga: Record<string, unknown> = { iss: this.#firmante.did, htm: metodo, htu: ruta, iat: ahoraEnSegundos(), jti: randomUUID() };
    if (this.#firmante.delegacion) carga.delegation = this.#firmante.delegacion;
    return `Vinculo ${this.#firmante.firmar({ typ: TIPO_ACCESO }, carga)}`;
  }

  async retirar(): Promise<SobreGuardado[]> {
    const ruta = camino('v1', 'buzon', this.#persona);
    const respuesta = await fetch(this.#base + ruta, { headers: { authorization: this.#autorizacion('GET', ruta) } });
    await exigir(respuesta, 200, 'el buzón negó el acceso');
    return ((await respuesta.json()) as { sobres: SobreGuardado[] }).sobres;
  }

  async borrar(id: string): Promise<void> {
    const ruta = camino('v1', 'buzon', this.#persona, id);
    const respuesta = await fetch(this.#base + ruta, { method: 'DELETE', headers: { authorization: this.#autorizacion('DELETE', ruta) } });
    await exigir(respuesta, 204, 'no se pudo borrar el sobre');
  }
}
