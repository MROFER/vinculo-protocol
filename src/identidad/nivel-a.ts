// Nivel A, autovinculación: la persona firma con el certificado de su documento de identidad
// (firma electrónica avanzada) una declaración que vincula su DID. Formato: JWS RS256 con la
// cadena de certificados en `x5c` (RFC 7515). No requiere nada nuevo del Estado.
import { X509Certificate, sign, type KeyObject } from 'node:crypto';
import { aBase64url } from '../codec.ts';
import { ahoraEnSegundos, decodificarJws, verificarJws } from '../jose.ts';
import { comprobarRevocacion, leerCrl, usosDeClave, type ListaRevocacion } from './x509.ts';

export const TIPO_VINCULACION = 'vinculo-vinculacion+jws';

/**
 * Quien firma con el documento. En un documento real la clave privada nunca sale del chip:
 * `firmarRs256` lo resolvería el middleware PKCS#11 del lector, con el PIN de la persona.
 */
export interface FirmanteDocumento {
  /** Certificados en PEM: primero el del titular, después las autoridades intermedias. */
  cadenaPem: string[];
  firmarRs256(datos: Buffer): Buffer;
}

export interface Vinculacion {
  did: string;
  iat: number;
  declaracion: string;
}

export interface ResultadoVinculacion {
  did: string;
  titular: { nombre: string; documento: string; pais: string };
  emisor: string;
  firmado: number;
}

/** Firmante para pruebas, con la clave en memoria (solo para la autoridad certificadora simulada). */
export function firmanteDeClave(cadenaPem: string[], privada: KeyObject): FirmanteDocumento {
  return { cadenaPem, firmarRs256: (datos) => sign('sha256', datos, privada) };
}

export function firmarVinculacion(firmante: FirmanteDocumento, did: string, ahora = ahoraEnSegundos()): string {
  const cabecera = {
    alg: 'RS256',
    typ: TIPO_VINCULACION,
    x5c: firmante.cadenaPem.map((pem) => new X509Certificate(pem).raw.toString('base64')),
  };
  const carga: Vinculacion = { did, iat: ahora, declaracion: `El titular de este documento controla el identificador ${did}.` };
  const entrada = `${aBase64url(JSON.stringify(cabecera))}.${aBase64url(JSON.stringify(carga))}`;
  return `${entrada}.${aBase64url(firmante.firmarRs256(Buffer.from(entrada, 'ascii')))}`;
}

function nombreDistinguido(texto: string): Record<string, string> {
  const campos: Record<string, string> = {};
  for (const linea of texto.split('\n')) {
    const igual = linea.indexOf('=');
    if (igual > 0) campos[linea.slice(0, igual)] = linea.slice(igual + 1);
  }
  return campos;
}

function vigente(certificado: X509Certificate, fecha: Date): boolean {
  return fecha >= new Date(certificado.validFrom) && fecha <= new Date(certificado.validTo);
}

/** Una autoridad puede firmar certificados si su uso de clave lo permite (o si no lo restringe). */
function puedeEmitirCertificados(certificado: X509Certificate): boolean {
  const usos = usosDeClave(certificado);
  return !usos || usos.has('keyCertSign');
}

function validarCadena(cadena: X509Certificate[], anclas: X509Certificate[], ahora: number, listas: ListaRevocacion[]): void {
  const fecha = new Date(ahora * 1000);
  const emisores: X509Certificate[] = [];
  cadena.forEach((certificado, i) => {
    if (!vigente(certificado, fecha)) throw new Error(`certificado fuera de vigencia: ${certificado.subject.replaceAll('\n', ', ')}`);
    if (i === 0 && certificado.ca) throw new Error('el certificado del titular no puede ser de una autoridad');
    // El documento trae un certificado de autenticación y otro de firma: la vinculación exige el de firma.
    if (i === 0 && !usosDeClave(certificado)?.has('nonRepudiation')) {
      throw new Error('el certificado del titular no es de firma (le falta el uso «no repudio»)');
    }
    if (i > 0 && !certificado.ca) throw new Error('un certificado intermedio no es de una autoridad');
    if (i > 0 && !puedeEmitirCertificados(certificado)) throw new Error('una autoridad de la cadena no está autorizada a emitir certificados');
    const siguiente = cadena[i + 1];
    if (siguiente) {
      if (!certificado.checkIssued(siguiente) || !certificado.verify(siguiente.publicKey)) throw new Error('la cadena de certificados está rota');
      emisores.push(siguiente);
      return;
    }
    const ancla = anclas.find((a) => certificado.checkIssued(a) && certificado.verify(a.publicKey));
    if (!ancla) throw new Error('la cadena no termina en una raíz de confianza');
    if (!vigente(ancla, fecha)) throw new Error('la raíz de confianza está fuera de vigencia');
    if (!puedeEmitirCertificados(ancla)) throw new Error('la raíz de confianza no está autorizada a emitir certificados');
    emisores.push(ancla);
  });
  // Con la cadena completa: cada certificado se busca en una lista de revocación vigente de su emisor.
  cadena.forEach((certificado, i) => comprobarRevocacion(certificado, emisores[i], listas, fecha));
}

export interface OpcionesVinculacion {
  /**
   * Listas de revocación (CRL, en PEM o DER) de cada autoridad de la cadena, vigentes. En producción se
   * descargan de los puntos de distribución de los certificados y se renuevan antes de que venzan.
   */
  crls: Array<string | Buffer>;
  did?: string;
  ahora?: number;
}

/**
 * Verifica una vinculación contra las raíces de confianza configuradas (en producción, la raíz nacional
 * que publica la UCE) y las listas de revocación de cada autoridad. Devuelve quién es el titular.
 */
export function verificarVinculacion(jws: string, anclas: X509Certificate[], opciones: OpcionesVinculacion): ResultadoVinculacion {
  const ahora = opciones.ahora ?? ahoraEnSegundos();
  const { cabecera, carga } = decodificarJws<Vinculacion>(jws);
  if (cabecera.typ !== TIPO_VINCULACION) throw new Error('no es una vinculación de nivel A');
  if (!Array.isArray(cabecera.x5c) || cabecera.x5c.length === 0) throw new Error('falta la cadena de certificados');
  const cadena = cabecera.x5c.map((b64) => new X509Certificate(Buffer.from(b64, 'base64')));
  validarCadena(cadena, anclas, ahora, opciones.crls.map(leerCrl));
  verificarJws(jws, cadena[0].publicKey, 'RS256');
  if (opciones.did && carga.did !== opciones.did) throw new Error('la vinculación es para otro DID');
  if (carga.iat > ahora + 300) throw new Error('la vinculación tiene fecha futura');
  const titular = nombreDistinguido(cadena[0].subject);
  return {
    did: carga.did,
    titular: { nombre: titular.CN ?? '', documento: titular.serialNumber ?? '', pais: titular.C ?? '' },
    emisor: nombreDistinguido(cadena[0].issuer).CN ?? '',
    firmado: carga.iat,
  };
}
