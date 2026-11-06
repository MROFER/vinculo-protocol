// Registro de mensajes ya procesados, para rechazar repeticiones (SPEC, sección 7, paso 6).
// Es de la persona, no del agente: tiene que sobrevivir a la renovación del agente y, guardado en un archivo,
// a un reinicio. Cada entrada se olvida cuando su mensaje vence, porque un mensaje vencido ya se rechaza solo.
import { readFileSync } from 'node:fs';
import { escribirAtomico } from './archivos.ts';

export interface RegistroVistos {
  /** Verdadero si el mensaje ya se procesó. */
  visto(clave: string, ahora: number): boolean;
  /** Anota el mensaje hasta que venza. Devuelve falso si ya estaba anotado. */
  anotar(clave: string, vence: number, ahora: number): boolean;
}

/** La clave de un mensaje: el identificador lo elige quien envía, así que se combina con su DID. */
export const claveDeMensaje = (remitente: string, id: string) => `${remitente} ${id}`;

export class VistosEnMemoria implements RegistroVistos {
  #vencen: Map<string, number>;

  constructor(entradas: Iterable<[string, number]> = []) {
    this.#vencen = new Map(entradas);
  }

  visto(clave: string, ahora: number): boolean {
    const vence = this.#vencen.get(clave);
    return vence !== undefined && vence >= ahora;
  }

  anotar(clave: string, vence: number, ahora: number): boolean {
    for (const [otra, hasta] of this.#vencen) if (hasta < ahora) this.#vencen.delete(otra);
    if (this.#vencen.has(clave)) return false;
    this.#vencen.set(clave, vence);
    return true;
  }

  get entradas(): [string, number][] {
    return [...this.#vencen];
  }
}

/** Igual que en memoria, pero guardado en un archivo JSON después de cada mensaje nuevo. */
export class VistosEnArchivo implements RegistroVistos {
  #ruta: string;
  #memoria: VistosEnMemoria;

  constructor(ruta: string) {
    this.#ruta = ruta;
    let guardado: Record<string, number> = {};
    try {
      guardado = JSON.parse(readFileSync(ruta, 'utf8')) as Record<string, number>;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        // Mejor no arrancar que arrancar olvidando qué mensajes ya llegaron.
        throw new Error(`no se pudo leer el registro de mensajes vistos (${ruta}): ${(error as Error).message}`);
      }
    }
    this.#memoria = new VistosEnMemoria(Object.entries(guardado).filter((par): par is [string, number] => typeof par[1] === 'number'));
  }

  visto(clave: string, ahora: number): boolean {
    return this.#memoria.visto(clave, ahora);
  }

  anotar(clave: string, vence: number, ahora: number): boolean {
    if (!this.#memoria.anotar(clave, vence, ahora)) return false;
    escribirAtomico(this.#ruta, JSON.stringify(Object.fromEntries(this.#memoria.entradas)));
    return true;
  }
}
