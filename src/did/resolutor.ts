// Resolución de DIDs con métodos intercambiables: did:key (local), did:web y did:xrpl (XLS-40, en xrpl.ts).
import { documentoDidKey } from './clave.ts';
import type { DocumentoDid } from './documento.ts';

export interface MetodoDid {
  resolver(did: string): Promise<DocumentoDid>;
}

type Fetch = typeof fetch;

export class Resolutor {
  #metodos: Map<string, MetodoDid>;

  constructor(metodos: Record<string, MetodoDid> = {}) {
    this.#metodos = new Map(Object.entries({ key: new MetodoKey(), ...metodos }));
  }

  async resolver(did: string): Promise<DocumentoDid> {
    const partes = did.split(':');
    if (partes.length < 3 || partes[0] !== 'did') throw new Error(`DID mal formado: ${did}`);
    const metodo = this.#metodos.get(partes[1]);
    if (!metodo) throw new Error(`método DID no soportado: did:${partes[1]}`);
    const documento = await metodo.resolver(did);
    if (documento.id !== did) throw new Error(`el documento resuelto no corresponde a ${did}`);
    return normalizar(documento);
  }
}

/** Convierte las referencias relativas ("#clave-1") en absolutas. */
function normalizar(doc: DocumentoDid): DocumentoDid {
  const absoluta = (ref: string) => (ref.startsWith('#') ? doc.id + ref : ref);
  return {
    ...doc,
    verificationMethod: doc.verificationMethod?.map((m) => ({ ...m, id: absoluta(m.id), controller: m.controller ?? doc.id })),
    authentication: doc.authentication?.map(absoluta),
    assertionMethod: doc.assertionMethod?.map(absoluta),
    capabilityDelegation: doc.capabilityDelegation?.map(absoluta),
    keyAgreement: doc.keyAgreement?.map(absoluta),
    service: doc.service?.map((s) => ({ ...s, id: absoluta(s.id) })),
  };
}

export class MetodoKey implements MetodoDid {
  async resolver(did: string): Promise<DocumentoDid> {
    return documentoDidKey(did);
  }
}

/** did:web: el documento vive en un dominio (por ejemplo, el de un organismo público). */
export class MetodoWeb implements MetodoDid {
  #fetch: Fetch;
  #esquema: string;

  constructor(opciones: { fetch?: Fetch; soloParaPruebasHttp?: boolean } = {}) {
    this.#fetch = opciones.fetch ?? fetch;
    this.#esquema = opciones.soloParaPruebasHttp ? 'http' : 'https';
  }

  static url(did: string, esquema = 'https'): string {
    const [, , dominio, ...ruta] = did.split(':');
    const host = decodeURIComponent(dominio);
    if (ruta.length === 0) return `${esquema}://${host}/.well-known/did.json`;
    return `${esquema}://${host}/${ruta.map(decodeURIComponent).join('/')}/did.json`;
  }

  async resolver(did: string): Promise<DocumentoDid> {
    const url = MetodoWeb.url(did, this.#esquema);
    const respuesta = await this.#fetch(url);
    if (!respuesta.ok) throw new Error(`did:web: ${url} respondió ${respuesta.status}`);
    return (await respuesta.json()) as DocumentoDid;
  }
}
