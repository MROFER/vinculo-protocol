// Identidades de la demostración del complemento: Maxi (que usa Claude) y Mamá (con un agente simulado).
// Se guardan en una carpeta local (por defecto datos/, que git ignora) para que el complemento y la red de
// prueba compartan las mismas personas. Son claves de PRUEBA: en un teléfono real vivirían en la billetera.
// Si Maxi registró su identidad en la red de prueba de XRP Ledger (npm run xrpl:registrar), su DID es ese did:xrpl.
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Agenda } from '../agenda.ts';
import { escribirAtomico } from '../archivos.ts';
import { Billetera } from '../billetera.ts';
import { aBase64url, deBase64url } from '../codec.ts';
import { Resolutor } from '../did/resolutor.ts';
import { MetodoXrpl, RED_DE_PRUEBA } from '../did/xrpl.ts';

export const BUZON_POR_DEFECTO = 'http://127.0.0.1:8787';
const CARPETA_POR_DEFECTO = fileURLToPath(new URL('../../datos/', import.meta.url));
const ARCHIVO_XRPL = 'xrpl.json';

interface ArchivoDemo {
  version: 1;
  aviso: string;
  maxi: { nombre: string; semilla: string };
  mama: { nombre: string; semilla: string };
}

/** Cuenta de Maxi en la red de prueba de XRP Ledger. La crea y la mantiene «npm run xrpl:registrar». */
export interface RegistroXrpl {
  version: 1;
  aviso: string;
  /** NetworkID de la red: 1 es la red de prueba. */
  red: string;
  /** Semilla de la cuenta XRPL que controla el objeto DID. No es la clave de Vínculo de Maxi. */
  semilla: string;
  cuenta: string;
  /** Se completan cuando el objeto DID quedó en un ledger validado. */
  did?: string;
  transaccion?: string;
  registrado?: string;
}

/** Lo público del registro: lo que el resto de la demostración necesita saber. */
export interface IdentidadXrpl {
  did: string;
  cuenta: string;
  red: string;
  transaccion?: string;
}

export interface Persona {
  nombre: string;
  billetera: Billetera;
  agenda: Agenda;
}

export interface IdentidadesDemo {
  carpeta: string;
  buzon: string;
  maxi: Persona;
  mama: Persona;
  /** Presente si Maxi registró su identidad en la XRP Ledger. */
  xrpl?: IdentidadXrpl;
}

export interface OpcionesIdentidades {
  carpeta: string;
  buzon: string;
}

/** Lee la carpeta y el buzón de las variables VINCULO_DATOS y VINCULO_BUZON, con valores por defecto. */
export function opcionesDeEntorno(entorno: NodeJS.ProcessEnv = process.env): OpcionesIdentidades {
  return {
    carpeta: entorno.VINCULO_DATOS || CARPETA_POR_DEFECTO,
    buzon: entorno.VINCULO_BUZON || BUZON_POR_DEFECTO,
  };
}

function leerOCrear(carpeta: string): ArchivoDemo {
  const ruta = join(carpeta, 'demo.json');
  const leer = () => JSON.parse(readFileSync(ruta, 'utf8')) as ArchivoDemo;
  try {
    return leer();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const nuevo: ArchivoDemo = {
    version: 1,
    aviso: 'Claves de PRUEBA de la demostración de Vínculo. No usar para nada real.',
    maxi: { nombre: 'Maxi', semilla: aBase64url(randomBytes(32)) },
    mama: { nombre: 'Mamá', semilla: aBase64url(randomBytes(32)) },
  };
  // Si dos procesos arrancan a la vez, uno crea el archivo completo y el otro lee el del primero.
  return escribirAtomico(ruta, JSON.stringify(nuevo, null, 2), { soloSiNoExiste: true }) ? nuevo : leer();
}

export function leerRegistroXrpl(carpeta: string): RegistroXrpl | null {
  try {
    return JSON.parse(readFileSync(join(carpeta, ARCHIVO_XRPL), 'utf8')) as RegistroXrpl;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

export function guardarRegistroXrpl(carpeta: string, registro: RegistroXrpl): void {
  escribirAtomico(join(carpeta, ARCHIVO_XRPL), JSON.stringify(registro, null, 2));
}

/** Resolutor de la demostración: did:key y did:xrpl de la red de prueba de XRP Ledger. */
export function crearResolutor(opciones: { fetch?: typeof fetch } = {}): Resolutor {
  return new Resolutor({
    xrpl: new MetodoXrpl({ servidores: { [RED_DE_PRUEBA.red]: RED_DE_PRUEBA.jsonRpc }, fetch: opciones.fetch }),
  });
}

/** Carga a Maxi y a Mamá (o las crea la primera vez), con sus agendas ya intercambiadas. */
export function cargarIdentidades(opciones: OpcionesIdentidades = opcionesDeEntorno()): IdentidadesDemo {
  const archivo = leerOCrear(opciones.carpeta);
  const registro = leerRegistroXrpl(opciones.carpeta);
  const xrpl: IdentidadXrpl | undefined = registro?.did
    ? { did: registro.did, cuenta: registro.cuenta, red: registro.red, transaccion: registro.transaccion }
    : undefined;
  // La clave de Maxi es la misma con o sin registro; lo que cambia es el DID con el que se presenta.
  const billeteraMaxi = Billetera.desdeSemilla(deBase64url(archivo.maxi.semilla), { did: xrpl?.did });
  const billeteraMama = Billetera.desdeSemilla(deBase64url(archivo.mama.semilla));

  // Se conocieron en persona e intercambiaron tarjetas: cada uno tiene al otro en su agenda.
  const agendaMaxi = new Agenda();
  agendaMaxi.agregar({
    did: billeteraMama.did,
    nombre: archivo.mama.nombre,
    alias: ['madre', 'mami', 'vieja'],
    buzon: opciones.buzon,
    verificadoEnPersona: true,
    permisos: { llamar: true },
  });
  const agendaMama = new Agenda();
  agendaMama.agregar({
    did: billeteraMaxi.did,
    nombre: archivo.maxi.nombre,
    alias: ['hijo'],
    buzon: opciones.buzon,
    verificadoEnPersona: true,
    permisos: { llamar: true },
  });

  return {
    carpeta: opciones.carpeta,
    buzon: opciones.buzon,
    maxi: { nombre: archivo.maxi.nombre, billetera: billeteraMaxi, agenda: agendaMaxi },
    mama: { nombre: archivo.mama.nombre, billetera: billeteraMama, agenda: agendaMama },
    ...(xrpl ? { xrpl } : {}),
  };
}
