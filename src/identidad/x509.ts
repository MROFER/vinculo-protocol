// Lo que node:crypto no expone de X.509: el uso de clave de un certificado y las listas de revocación (CRL,
// RFC 5280). Un lector DER mínimo: solo etiquetas de un byte y largos definidos, que es lo que usan.
import { verify, type X509Certificate } from 'node:crypto';

interface Tlv {
  etiqueta: number;
  /** El contenido, sin etiqueta ni largo. */
  contenido: Buffer;
  /** El elemento completo, tal como está codificado. */
  completo: Buffer;
}

const ETIQUETA = { booleano: 0x01, entero: 0x02, bits: 0x03, octetos: 0x04, oid: 0x06, secuencia: 0x30, utc: 0x17, generalizada: 0x18 };

function leerTlv(datos: Buffer, desde: number): { tlv: Tlv; hasta: number } {
  if (desde + 2 > datos.length) throw new Error('DER truncado');
  const etiqueta = datos[desde];
  if ((etiqueta & 0x1f) === 0x1f) throw new Error('DER: etiqueta no soportada');
  let largo = datos[desde + 1];
  let inicio = desde + 2;
  if (largo & 0x80) {
    const bytes = largo & 0x7f;
    if (bytes === 0 || bytes > 4 || inicio + bytes > datos.length) throw new Error('DER: largo no soportado');
    largo = 0;
    for (let i = 0; i < bytes; i++) largo = largo * 256 + datos[inicio + i];
    inicio += bytes;
  }
  const hasta = inicio + largo;
  if (hasta > datos.length) throw new Error('DER truncado');
  return { tlv: { etiqueta, contenido: datos.subarray(inicio, hasta), completo: datos.subarray(desde, hasta) }, hasta };
}

function unico(datos: Buffer): Tlv {
  const { tlv, hasta } = leerTlv(datos, 0);
  if (hasta !== datos.length) throw new Error('DER: sobran datos');
  return tlv;
}

function hijos(tlv: Tlv): Tlv[] {
  const lista: Tlv[] = [];
  for (let pos = 0; pos < tlv.contenido.length; ) {
    const { tlv: hijo, hasta } = leerTlv(tlv.contenido, pos);
    lista.push(hijo);
    pos = hasta;
  }
  return lista;
}

function oid(tlv: Tlv): string {
  if (tlv.etiqueta !== ETIQUETA.oid || tlv.contenido.length === 0) throw new Error('DER: se esperaba un OID');
  const partes: number[] = [];
  let valor = 0;
  for (const byte of tlv.contenido) {
    valor = valor * 128 + (byte & 0x7f);
    if (!(byte & 0x80)) {
      partes.push(valor);
      valor = 0;
    }
  }
  const primero = Math.min(Math.floor(partes[0] / 40), 2);
  return [primero, partes[0] - primero * 40, ...partes.slice(1)].join('.');
}

/** Un entero como hexadecimal sin ceros a la izquierda: así se comparan números de serie. */
function enteroHex(tlv: Tlv): string {
  if (tlv.etiqueta !== ETIQUETA.entero) throw new Error('DER: se esperaba un entero');
  let i = 0;
  while (i < tlv.contenido.length - 1 && tlv.contenido[i] === 0) i++;
  return tlv.contenido.subarray(i).toString('hex').toUpperCase();
}

function fecha(tlv: Tlv): Date {
  const texto = tlv.contenido.toString('ascii');
  const coincide =
    tlv.etiqueta === ETIQUETA.utc
      ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(texto)
      : tlv.etiqueta === ETIQUETA.generalizada
        ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(texto)
        : null;
  if (!coincide) throw new Error('DER: fecha no soportada');
  const [, a, mes, dia, hora, minuto, segundo] = coincide.map(Number);
  // RFC 5280: en UTCTime, 50 a 99 son 1950 a 1999.
  const anio = tlv.etiqueta === ETIQUETA.utc ? (a >= 50 ? 1900 + a : 2000 + a) : a;
  return new Date(Date.UTC(anio, mes - 1, dia, hora, minuto, segundo));
}

function bits(tlv: Tlv): Buffer {
  if (tlv.etiqueta !== ETIQUETA.bits || tlv.contenido.length === 0) throw new Error('DER: se esperaba una cadena de bits');
  return tlv.contenido.subarray(1);
}

interface Extension {
  critica: boolean;
  valor: Buffer;
}

function extensiones(secuencia: Tlv): Map<string, Extension> {
  const mapa = new Map<string, Extension>();
  for (const extension of hijos(secuencia)) {
    const partes = hijos(extension);
    const critica = partes.length === 3 && partes[1].etiqueta === ETIQUETA.booleano && partes[1].contenido[0] !== 0;
    mapa.set(oid(partes[0]), { critica, valor: partes[partes.length - 1].contenido });
  }
  return mapa;
}

/** Los campos de un certificado que hacen falta para revocación y usos de clave. */
function partesDeCertificado(certificado: X509Certificate) {
  const [tbs] = hijos(unico(certificado.raw));
  const campos = hijos(tbs);
  const i = campos[0].etiqueta === 0xa0 ? 1 : 0; // versión, opcional
  const extras = campos.slice(i + 6).find((campo) => campo.etiqueta === 0xa3);
  return {
    serie: enteroHex(campos[i]),
    emisor: campos[i + 2].completo,
    extensiones: extras ? extensiones(hijos(extras)[0]) : new Map<string, Extension>(),
  };
}

const USOS = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign'] as const;
export type UsoDeClave = (typeof USOS)[number];

/** Los usos de clave (extensión keyUsage), o null si el certificado no la trae. */
export function usosDeClave(certificado: X509Certificate): Set<UsoDeClave> | null {
  const extension = partesDeCertificado(certificado).extensiones.get('2.5.29.15');
  if (!extension) return null;
  const marcados = bits(unico(extension.valor));
  return new Set(USOS.filter((_, i) => (marcados[i >> 3] ?? 0) & (0x80 >> (i & 7))));
}

export interface ListaRevocacion {
  /** Nombre del emisor, tal como está codificado: se compara byte a byte con el del certificado. */
  emisor: Buffer;
  firmada: Buffer;
  algoritmo: string;
  firma: Buffer;
  desde: Date;
  hasta?: Date;
  revocados: Set<string>;
  /** Trae extensiones críticas (por ejemplo, de una CRL delta o particionada) que este verificador no soporta. */
  criticas: boolean;
}

/** Lee una CRL en PEM o DER. No la verifica: eso lo hace comprobarRevocacion, con el certificado del emisor. */
export function leerCrl(crl: string | Buffer): ListaRevocacion {
  const der = typeof crl === 'string' ? Buffer.from(crl.replace(/-----(BEGIN|END) X509 CRL-----|\s+/g, ''), 'base64') : crl;
  const [tbs, algoritmo, firma] = hijos(unico(der));
  const campos = hijos(tbs);
  const i = campos[0].etiqueta === ETIQUETA.entero ? 1 : 0; // versión, opcional
  if (!campos[i].completo.equals(algoritmo.completo)) throw new Error('la CRL declara dos algoritmos de firma distintos');
  let j = i + 3;
  let hasta: Date | undefined;
  if (campos[j]?.etiqueta === ETIQUETA.utc || campos[j]?.etiqueta === ETIQUETA.generalizada) hasta = fecha(campos[j++]);
  const revocados = new Set<string>();
  let criticas = false;
  if (campos[j]?.etiqueta === ETIQUETA.secuencia) {
    for (const entrada of hijos(campos[j++])) {
      const partes = hijos(entrada);
      revocados.add(enteroHex(partes[0]));
      if (partes[2] && [...extensiones(partes[2]).values()].some((e) => e.critica)) criticas = true;
    }
  }
  if (campos[j]?.etiqueta === 0xa0 && [...extensiones(hijos(campos[j])[0]).values()].some((e) => e.critica)) criticas = true;
  return {
    emisor: campos[i + 1].completo,
    firmada: tbs.completo,
    algoritmo: oid(hijos(algoritmo)[0]),
    firma: bits(firma),
    desde: fecha(campos[i + 2]),
    hasta,
    revocados,
    criticas,
  };
}

const RESUMEN_DE_FIRMA: Record<string, string> = {
  '1.2.840.113549.1.1.11': 'sha256', // sha256WithRSAEncryption
  '1.2.840.113549.1.1.12': 'sha384',
  '1.2.840.113549.1.1.13': 'sha512',
  '1.2.840.10045.4.3.2': 'sha256', // ecdsa-with-SHA256
  '1.2.840.10045.4.3.3': 'sha384',
  '1.2.840.10045.4.3.4': 'sha512',
};

const nombreComun = (certificado: X509Certificate) => /(?:^|\n)CN=([^\n]*)/.exec(certificado.subject)?.[1] ?? certificado.subject;

/**
 * Comprueba con las CRL de su emisor que un certificado no fue revocado. Hace falta al menos una lista del
 * emisor, firmada por él y vigente en la fecha dada; si alguna de esas lo incluye, está revocado.
 */
export function comprobarRevocacion(certificado: X509Certificate, emisor: X509Certificate, listas: ListaRevocacion[], momento: Date): void {
  const { serie, emisor: nombreDelEmisor } = partesDeCertificado(certificado);
  const delEmisor = listas.filter((lista) => lista.emisor.equals(nombreDelEmisor));
  if (delEmisor.length === 0) throw new Error(`falta la lista de revocación de «${nombreComun(emisor)}»`);
  const usos = usosDeClave(emisor);
  if (usos && !usos.has('cRLSign')) throw new Error(`«${nombreComun(emisor)}» no está autorizada a emitir listas de revocación`);

  let motivo = '';
  let vigentes = 0;
  for (const lista of delEmisor) {
    const resumen = RESUMEN_DE_FIRMA[lista.algoritmo];
    if (lista.criticas) motivo = 'usa extensiones críticas que este verificador no soporta';
    else if (!resumen) motivo = `usa un algoritmo de firma no soportado (${lista.algoritmo})`;
    else if (!verify(resumen, lista.firmada, emisor.publicKey, lista.firma)) motivo = 'no está firmada por su autoridad';
    else if (!lista.hasta || momento < lista.desde || momento > lista.hasta) motivo = 'está vencida';
    else {
      vigentes += 1;
      if (lista.revocados.has(serie)) throw new Error(`el certificado de «${nombreComun(certificado)}» fue revocado`);
    }
  }
  if (vigentes === 0) throw new Error(`la lista de revocación de «${nombreComun(emisor)}» ${motivo}`);
}
