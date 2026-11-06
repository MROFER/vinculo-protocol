// Buzón (mediador): guarda sobres cifrados hasta que el agente de la persona los retira.
// No puede leerlos: solo conoce el DID destinatario, el tamaño y la hora de llegada.
// Cualquiera puede depositar; solo la persona, o un agente con delegación vigente, puede retirar.
import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { publicaEd25519 } from '../cripto/claves.ts';
import { ALCANCE, verificarDelegacion, verificarRevocaciones } from '../delegacion.ts';
import { claveDeFirma } from '../did/documento.ts';
import type { Resolutor } from '../did/resolutor.ts';
import { ahoraEnSegundos, decodificarJws, verificarJws } from '../jose.ts';

export const TIPO_ACCESO = 'vinculo-acceso+jws';

export interface SobreGuardado {
  id: string;
  recibido: number;
  jwe: string;
}

export interface CargaAcceso {
  iss: string;
  htm: string;
  htu: string;
  iat: number;
  jti: string;
  delegation?: string;
}

export interface OpcionesBuzon {
  resolutor: Resolutor;
  tamanoMaximo?: number;
  maxPorDestinatario?: number;
  /** Segundos de tolerancia para la hora de una autorización. */
  ventana?: number;
  ahora?: () => number;
}

class ErrorHttp extends Error {
  estado: number;
  constructor(estado: number, mensaje: string) {
    super(mensaje);
    this.estado = estado;
  }
}

function responder(res: ServerResponse, estado: number, cuerpo?: unknown): void {
  if (cuerpo === undefined) {
    res.writeHead(estado).end();
    return;
  }
  res.writeHead(estado, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify(cuerpo));
}

/**
 * Lee el cuerpo de un pedido hasta `limite` bytes. Si el largo declarado ya lo supera, no lee nada; si lo
 * supera mientras llega, deja de leer en ese momento. En los dos casos la respuesta 413 cierra la conexión.
 */
export function leerCuerpo(req: IncomingMessage, limite: number): Promise<string> {
  return new Promise((resolver, rechazar) => {
    const demasiadoGrande = () => new ErrorHttp(413, `el sobre supera ${limite} bytes`);
    if (Number(req.headers['content-length'] ?? 0) > limite) {
      rechazar(demasiadoGrande());
      return;
    }
    const trozos: Buffer[] = [];
    let total = 0;
    const alRecibir = (trozo: Buffer) => {
      total += trozo.length;
      if (total <= limite) {
        trozos.push(trozo);
        return;
      }
      req.off('data', alRecibir);
      req.pause();
      rechazar(demasiadoGrande());
    };
    req.on('data', alRecibir);
    req.on('end', () => resolver(Buffer.concat(trozos).toString('utf8')));
    req.on('error', rechazar);
  });
}

export class ServidorBuzon {
  #resolutor: Resolutor;
  #tamanoMaximo: number;
  #maxPorDestinatario: number;
  #ventana: number;
  #ahora: () => number;
  #sobres = new Map<string, SobreGuardado[]>();
  #revocaciones = new Map<string, { jwt: string; version: number; revocadas: Set<string> }>();
  #accesosUsados = new Map<string, number>();
  #servidor: Server | undefined;
  #url = '';

  constructor(opciones: OpcionesBuzon) {
    this.#resolutor = opciones.resolutor;
    this.#tamanoMaximo = opciones.tamanoMaximo ?? 64 * 1024;
    this.#maxPorDestinatario = opciones.maxPorDestinatario ?? 500;
    this.#ventana = opciones.ventana ?? 120;
    this.#ahora = opciones.ahora ?? ahoraEnSegundos;
  }

  get url(): string {
    return this.#url;
  }

  async iniciar(puerto = 0, host = '127.0.0.1'): Promise<string> {
    const servidor = createServer((req, res) => {
      this.#atender(req, res).catch((error: unknown) => {
        const estado = error instanceof ErrorHttp ? error.estado : 500;
        // Ante un pedido demasiado grande se cierra la conexión: así no se sigue recibiendo lo que falta.
        if (estado === 413) res.setHeader('connection', 'close');
        responder(res, estado, { error: error instanceof Error ? error.message : String(error) });
      });
    });
    // Si el puerto está ocupado, el error llega como evento: se convierte en rechazo de la promesa.
    await new Promise<void>((listo, fallo) => {
      servidor.once('error', fallo);
      servidor.listen(puerto, host, () => {
        servidor.off('error', fallo);
        listo();
      });
    });
    const direccion = servidor.address();
    if (!direccion || typeof direccion === 'string') throw new Error('no se pudo abrir el puerto del buzón');
    this.#servidor = servidor;
    this.#url = `http://${host}:${direccion.port}`;
    return this.#url;
  }

  async detener(): Promise<void> {
    const servidor = this.#servidor;
    if (!servidor) return;
    servidor.closeAllConnections();
    await new Promise<void>((listo, fallo) => servidor.close((error) => (error ? fallo(error) : listo())));
  }

  /** Lo que el buzón realmente tiene guardado para un DID: sirve para auditar qué puede ver. */
  inspeccionar(did: string): readonly SobreGuardado[] {
    return this.#sobres.get(did) ?? [];
  }

  async #atender(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://buzon');
    let partes: string[];
    try {
      partes = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
    } catch {
      throw new ErrorHttp(400, 'ruta mal codificada');
    }
    const [version, recurso, did, id] = partes;
    if (version !== 'v1' || !did) throw new ErrorHttp(404, 'ruta desconocida');

    if (recurso === 'buzon' && partes.length === 3 && req.method === 'POST') return this.#depositar(req, res, did);
    if (recurso === 'buzon' && partes.length === 3 && req.method === 'GET') {
      await this.#autorizar(req, did, 'GET', url.pathname);
      return responder(res, 200, { sobres: this.#sobres.get(did) ?? [] });
    }
    if (recurso === 'buzon' && partes.length === 4 && req.method === 'DELETE') {
      await this.#autorizar(req, did, 'DELETE', url.pathname);
      const cola = this.#sobres.get(did) ?? [];
      const indice = cola.findIndex((sobre) => sobre.id === id);
      if (indice < 0) throw new ErrorHttp(404, 'sobre inexistente');
      cola.splice(indice, 1);
      return responder(res, 204);
    }
    if (recurso === 'estado' && partes.length === 3 && req.method === 'PUT') return this.#publicarRevocaciones(req, res, did);
    if (recurso === 'estado' && partes.length === 3 && req.method === 'GET') {
      const actual = this.#revocaciones.get(did);
      if (!actual) throw new ErrorHttp(404, 'sin lista de revocaciones');
      return responder(res, 200, { revocaciones: actual.jwt });
    }
    throw new ErrorHttp(404, 'ruta desconocida');
  }

  async #depositar(req: IncomingMessage, res: ServerResponse, did: string): Promise<void> {
    const jwe = (await leerCuerpo(req, this.#tamanoMaximo)).trim();
    if (jwe.split('.').length !== 5) throw new ErrorHttp(400, 'se esperaba un JWE compacto');
    const cola = this.#sobres.get(did) ?? [];
    if (cola.length >= this.#maxPorDestinatario) throw new ErrorHttp(429, 'buzón lleno');
    const sobre: SobreGuardado = { id: randomUUID(), recibido: this.#ahora(), jwe };
    cola.push(sobre);
    this.#sobres.set(did, cola);
    responder(res, 202, { id: sobre.id });
  }

  async #publicarRevocaciones(req: IncomingMessage, res: ServerResponse, did: string): Promise<void> {
    const jwt = (await leerCuerpo(req, this.#tamanoMaximo)).trim();
    const lista = await verificarRevocaciones(jwt, this.#resolutor, did).catch((error: Error) => {
      throw new ErrorHttp(400, `lista de revocaciones inválida: ${error.message}`);
    });
    const actual = this.#revocaciones.get(did);
    // Impide volver a una lista vieja que "des-revoque" un agente.
    if (actual && lista.version <= actual.version) throw new ErrorHttp(409, 'ya hay una lista de revocaciones más nueva');
    this.#revocaciones.set(did, { jwt, version: lista.version, revocadas: new Set(lista.revocadas) });
    responder(res, 204);
  }

  async #autorizar(req: IncomingMessage, did: string, metodo: string, ruta: string): Promise<void> {
    const [esquema, token] = (req.headers.authorization ?? '').split(' ');
    if (esquema !== 'Vinculo' || !token) throw new ErrorHttp(401, 'falta la autorización Vinculo');
    let acceso: CargaAcceso;
    try {
      const { cabecera, carga } = decodificarJws<CargaAcceso>(token);
      if (cabecera.typ !== TIPO_ACCESO || !cabecera.kid?.startsWith(`${carga.iss}#`)) throw new Error('autorización mal formada');
      const documento = await this.#resolutor.resolver(carga.iss);
      verificarJws(token, publicaEd25519(claveDeFirma(documento, cabecera.kid, 'authentication')));
      acceso = carga;
    } catch (error) {
      throw new ErrorHttp(401, `autorización inválida: ${(error as Error).message}`);
    }

    const ahora = this.#ahora();
    if (Math.abs(ahora - acceso.iat) > this.#ventana) throw new ErrorHttp(401, 'autorización fuera de la ventana de tiempo');
    if (acceso.htm !== metodo || acceso.htu !== ruta) throw new ErrorHttp(401, 'la autorización es para otra operación');
    for (const [jti, vence] of this.#accesosUsados) if (vence < ahora) this.#accesosUsados.delete(jti);
    if (this.#accesosUsados.has(acceso.jti)) throw new ErrorHttp(401, 'autorización reutilizada');
    this.#accesosUsados.set(acceso.jti, ahora + this.#ventana);

    if (acceso.iss === did) return; // la propia persona
    if (!acceso.delegation) throw new ErrorHttp(403, 'el agente no presenta una delegación');
    try {
      await verificarDelegacion(acceso.delegation, this.#resolutor, {
        ahora,
        emisor: did,
        agente: acceso.iss,
        alcance: ALCANCE.leerBuzon,
        revocadas: this.#revocaciones.get(did)?.revocadas,
      });
    } catch (error) {
      throw new ErrorHttp(403, (error as Error).message);
    }
  }
}
