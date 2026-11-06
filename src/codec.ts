// Codificaciones del protocolo: base64url (JOSE), base58btc (multibase) y hexadecimal.

const ALFABETO_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function aBase64url(datos: Uint8Array | string): string {
  const bytes = typeof datos === 'string' ? Buffer.from(datos, 'utf8') : Buffer.from(datos);
  return bytes.toString('base64url');
}

export function deBase64url(texto: string): Buffer {
  if (typeof texto !== 'string' || !/^[A-Za-z0-9_-]*$/.test(texto)) {
    throw new Error('base64url inválido');
  }
  return Buffer.from(texto, 'base64url');
}

export function jsonDeBase64url<T>(texto: string): T {
  return JSON.parse(deBase64url(texto).toString('utf8')) as T;
}

export function aBase58btc(datos: Uint8Array): string {
  let ceros = 0;
  while (ceros < datos.length && datos[ceros] === 0) ceros++;
  let numero = 0n;
  for (const byte of datos) numero = (numero << 8n) | BigInt(byte);
  let salida = '';
  while (numero > 0n) {
    salida = ALFABETO_B58[Number(numero % 58n)] + salida;
    numero /= 58n;
  }
  return '1'.repeat(ceros) + salida;
}

export function deBase58btc(texto: string): Uint8Array {
  let numero = 0n;
  for (const caracter of texto) {
    const valor = ALFABETO_B58.indexOf(caracter);
    if (valor < 0) throw new Error(`carácter base58 inválido: ${caracter}`);
    numero = numero * 58n + BigInt(valor);
  }
  const bytes: number[] = [];
  while (numero > 0n) {
    bytes.unshift(Number(numero & 0xffn));
    numero >>= 8n;
  }
  let ceros = 0;
  while (ceros < texto.length && texto[ceros] === '1') ceros++;
  return Uint8Array.from([...new Array<number>(ceros).fill(0), ...bytes]);
}

export function deHex(texto: string): Buffer {
  if (typeof texto !== 'string' || !/^([0-9a-fA-F]{2})*$/.test(texto)) {
    throw new Error('hexadecimal inválido');
  }
  return Buffer.from(texto, 'hex');
}
