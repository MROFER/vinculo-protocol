// did:xrpl (XLS-40) con el perfil Vínculo (SPEC.md, sección 3.3).
// El DID es «did:xrpl:<red>:<cuenta>»: <cuenta> es la dirección de la cuenta que controla el objeto DID y <red>
// es el NetworkID de XRP Ledger (1 en la red de prueba). XLS-40 no fija qué número corresponde a cada red, así
// que el resolutor recibe explícitamente qué servidor consultar para cada número.
import { createHash } from 'node:crypto';
import { deHex } from '../codec.ts';
import { documentoDeUnaClave } from './clave.ts';
import { MULTICODEC_ED25519, multibaseDeClave, type DocumentoDid } from './documento.ts';
import type { MetodoDid } from './resolutor.ts';

type Fetch = typeof fetch;

/** Máximo de bytes de cada campo del objeto DID: URI, Data y DIDDocument. */
export const MAXIMO_CAMPO = 256;

/** Red de prueba de XRP Ledger (Testnet): sus XRP no tienen valor y la red se reinicia cada tanto. */
export const RED_DE_PRUEBA = {
  red: '1',
  jsonRpc: 'https://s.altnet.rippletest.net:51234/',
  websocket: 'wss://s.altnet.rippletest.net:51233/',
  explorador: 'https://testnet.xrpl.org',
} as const;

const CUENTA = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;

export function didXrpl(red: string | number, cuenta: string): string {
  if (!/^\d+$/.test(String(red)) || !CUENTA.test(cuenta)) throw new Error(`red o cuenta XRPL inválida: ${red}, ${cuenta}`);
  return `did:xrpl:${red}:${cuenta}`;
}

/**
 * Forma compacta del perfil Vínculo: lo que va en el campo DIDDocument. Un documento DID completo no entra en
 * 256 bytes, así que el ledger guarda solo la clave y el resolutor arma el documento igual que en did:key.
 */
export interface FormaCompacta {
  vinculo: 1;
  /** Clave Ed25519 de la persona, en multibase (z6Mk…). */
  clave: string;
  /** Buzón de la persona, por HTTPS. Opcional: también puede viajar en la tarjeta de contacto. */
  buzon?: string;
}

function validarForma(valor: unknown): FormaCompacta {
  const forma = valor as Partial<FormaCompacta>;
  if (forma.vinculo !== 1) throw new Error('el objeto DID usa una versión de la forma compacta que este resolutor no conoce');
  if (typeof forma.clave !== 'string') throw new Error('la forma compacta no tiene clave');
  if (forma.buzon !== undefined && (typeof forma.buzon !== 'string' || !forma.buzon.startsWith('https://'))) {
    throw new Error('el buzón de la forma compacta tiene que ser una URL HTTPS');
  }
  return forma as FormaCompacta;
}

/** Contenido del campo DIDDocument (JSON en UTF-8) para la clave Ed25519 de la persona. */
export function formaCompacta(clave: Uint8Array, buzon?: string): string {
  const forma = validarForma({ vinculo: 1, clave: multibaseDeClave(MULTICODEC_ED25519, clave), ...(buzon === undefined ? {} : { buzon }) });
  const json = JSON.stringify(forma);
  const bytes = Buffer.byteLength(json);
  if (bytes > MAXIMO_CAMPO) throw new Error(`la forma compacta ocupa ${bytes} bytes y el ledger admite ${MAXIMO_CAMPO}`);
  return json;
}

/** Lee el campo DIDDocument: la forma compacta del perfil Vínculo o, si no lo es, un documento DID completo. */
function documentoDelCampo(did: string, contenido: string): DocumentoDid {
  let valor: unknown;
  try {
    valor = JSON.parse(contenido);
  } catch {
    throw new Error('el campo DIDDocument del ledger no es JSON válido');
  }
  if (typeof valor !== 'object' || valor === null) throw new Error('el campo DIDDocument del ledger no es un objeto');
  if ('vinculo' in valor) {
    const forma = validarForma(valor);
    return documentoDeUnaClave(did, forma.clave, forma.buzon);
  }
  return valor as DocumentoDid;
}

interface NodoDid {
  LedgerEntryType?: string;
  Account?: string;
  URI?: string;
  Data?: string;
  DIDDocument?: string;
}

export interface OpcionesMetodoXrpl {
  /** Servidor JSON-RPC para cada número de red, por ejemplo { '1': RED_DE_PRUEBA.jsonRpc }. */
  servidores: Record<string, string>;
  fetch?: Fetch;
  /** Cuánto se guarda un documento ya resuelto, para no consultar el ledger en cada mensaje. Por defecto, 60 s. */
  cacheSegundos?: number;
  /** Cuántos documentos se guardan como máximo. Por defecto, 1000. */
  cacheMaximo?: number;
}

/**
 * Resuelve did:xrpl leyendo el objeto DID de la cuenta en un ledger validado. Acepta la forma compacta en
 * DIDDocument, o un documento externo: URI por HTTPS y su hash «sha256:<hex>» anclado en Data.
 */
export class MetodoXrpl implements MetodoDid {
  #servidores: Record<string, string>;
  #fetch: Fetch;
  #cacheMs: number;
  #cacheMaximo: number;
  #cache = new Map<string, { documento: DocumentoDid; vence: number }>();

  constructor(opciones: OpcionesMetodoXrpl) {
    this.#servidores = opciones.servidores;
    this.#fetch = opciones.fetch ?? fetch;
    this.#cacheMs = (opciones.cacheSegundos ?? 60) * 1000;
    this.#cacheMaximo = opciones.cacheMaximo ?? 1000;
  }

  /** Cuántos documentos hay guardados ahora. */
  get enCache(): number {
    return this.#cache.size;
  }

  async resolver(did: string): Promise<DocumentoDid> {
    const guardado = this.#cache.get(did);
    if (guardado && guardado.vence > Date.now()) return guardado.documento;
    this.#cache.delete(did);
    const documento = await this.#leerDelLedger(did);
    if (this.#cacheMs > 0 && this.#cacheMaximo > 0) this.#guardar(did, documento);
    return documento;
  }

  /** Guarda un documento sin pasar del máximo: primero se van los vencidos y, si no alcanza, los más viejos. */
  #guardar(did: string, documento: DocumentoDid): void {
    const ahora = Date.now();
    if (this.#cache.size >= this.#cacheMaximo) {
      for (const [clave, { vence }] of this.#cache) if (vence <= ahora) this.#cache.delete(clave);
      for (const clave of this.#cache.keys()) {
        if (this.#cache.size < this.#cacheMaximo) break;
        this.#cache.delete(clave);
      }
    }
    this.#cache.set(did, { documento, vence: ahora + this.#cacheMs });
  }

  async #leerDelLedger(did: string): Promise<DocumentoDid> {
    const partes = did.split(':');
    if (partes.length !== 4) throw new Error(`did:xrpl mal formado: ${did}`);
    const [, , red, cuenta] = partes;
    if (!CUENTA.test(cuenta)) throw new Error('el prototipo solo resuelve did:xrpl con dirección de cuenta');
    const servidor = this.#servidores[red];
    if (!servidor) throw new Error(`no hay servidor configurado para la red XRPL ${red}`);

    const respuesta = await this.#fetch(servidor, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ method: 'ledger_entry', params: [{ did: cuenta, ledger_index: 'validated' }] }),
    });
    if (!respuesta.ok) throw new Error(`el servidor XRPL respondió ${respuesta.status}`);
    const { result } = (await respuesta.json()) as { result?: { status?: string; error?: string; node?: NodoDid } };
    if (!result || result.status !== 'success' || !result.node) {
      if (result?.error === 'entryNotFound') throw new Error(`${did} no está registrado en el ledger`);
      throw new Error(`error del servidor XRPL: ${result?.error ?? 'respuesta inválida'}`);
    }
    const nodo = result.node;
    if (nodo.LedgerEntryType !== 'DID' || nodo.Account !== cuenta) {
      throw new Error('el objeto DID del ledger no corresponde a la cuenta');
    }

    if (nodo.URI) {
      const uri = deHex(nodo.URI).toString('utf8');
      if (!uri.startsWith('https://')) throw new Error(`URI no soportada por el prototipo: ${uri}`);
      const documento = await this.#fetch(uri);
      if (!documento.ok) throw new Error(`no se pudo obtener el documento DID (${documento.status})`);
      const bytes = Buffer.from(await documento.arrayBuffer());
      const anclado = nodo.Data ? deHex(nodo.Data).toString('utf8') : '';
      const calculado = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
      if (anclado !== calculado) throw new Error('el documento DID no coincide con el hash anclado en el ledger');
      return JSON.parse(bytes.toString('utf8')) as DocumentoDid;
    }
    if (nodo.DIDDocument) return documentoDelCampo(did, deHex(nodo.DIDDocument).toString('utf8'));
    throw new Error(`${did} no publica un documento (ni URI ni DIDDocument)`);
  }
}
