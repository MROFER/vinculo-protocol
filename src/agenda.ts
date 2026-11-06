// Agenda de contactos: las personas que conozco, por su DID, con alias y permisos.
// Un contacto es una persona, no un agente: si cambia de proveedor de IA, sigue siendo el mismo contacto.

export interface IdentidadEstatal {
  nivel: 'A' | 'B';
  emisor: string;
  nombre?: string;
  documento?: string;
}

export interface Contacto {
  did: string;
  nombre: string;
  alias: string[];
  buzon: string;
  verificadoEnPersona: boolean;
  identidadEstatal?: IdentidadEstatal;
  permisos: { llamar: boolean };
}

export function normalizarAlias(texto: string): string {
  return texto
    .normalize('NFD')
    .replace(/\p{Diacritic}/gu, '')
    .toLowerCase()
    .trim()
    .replace(/^(a\s+)?(mi|mis)\s+/, '')
    .trim();
}

export class Agenda {
  #contactos = new Map<string, Contacto>();

  agregar(contacto: Contacto): void {
    this.#contactos.set(contacto.did, contacto);
  }

  porDid(did: string): Contacto | undefined {
    return this.#contactos.get(did);
  }

  buscar(texto: string): Contacto | undefined {
    const buscado = normalizarAlias(texto);
    for (const contacto of this.#contactos.values()) {
      if ([contacto.nombre, ...contacto.alias].some((alias) => normalizarAlias(alias) === buscado)) return contacto;
    }
    return undefined;
  }

  get todos(): Contacto[] {
    return [...this.#contactos.values()];
  }
}
