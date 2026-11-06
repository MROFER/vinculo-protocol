import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { Agenda } from '../src/agenda.ts';
import { Agente } from '../src/agente.ts';
import { Billetera } from '../src/billetera.ts';
import { cargarIdentidades, guardarRegistroXrpl } from '../src/complemento/identidades.ts';
import { generarParEd25519 } from '../src/cripto/claves.ts';
import { ALCANCE, verificarDelegacion } from '../src/delegacion.ts';
import { buzonesDe } from '../src/did/documento.ts';
import { Resolutor } from '../src/did/resolutor.ts';
import { MAXIMO_CAMPO, MetodoXrpl, didXrpl, formaCompacta } from '../src/did/xrpl.ts';
import { ahoraEnSegundos } from '../src/jose.ts';
import { TIPOS } from '../src/mensajes.ts';
import { ServidorBuzon } from '../src/relay/servidor.ts';

const SERVIDOR = 'https://xrpl.example/';
const CUENTA = 'rpfqJrXg5uidNo2ZsRhRY6TiF1cvYmV9Fg';
const DID = didXrpl(1, CUENTA);
const claude = { nombre: 'Claude', proveedor: 'Anthropic', procesamiento: 'nube' as const };

/**
 * Ledger simulado: guarda el campo DIDDocument de cada cuenta y responde ledger_entry como un servidor JSON-RPC.
 * Solo contesta consultas sobre el último ledger validado, como exige la sección 3.3 de SPEC.md.
 */
class LedgerSimulado {
  consultas = 0;
  #objetos = new Map<string, string>();

  publicar(cuenta: string, contenido: string): void {
    this.#objetos.set(cuenta, Buffer.from(contenido).toString('hex').toUpperCase());
  }

  fetch: typeof fetch = async (entrada, init) => {
    if (String(entrada) !== SERVIDOR) return new Response('', { status: 404 });
    this.consultas += 1;
    const { method, params } = JSON.parse(String(init?.body)) as { method: string; params: [{ did: string; ledger_index?: string }] };
    if (method !== 'ledger_entry' || params[0].ledger_index !== 'validated') {
      return new Response(JSON.stringify({ result: { status: 'error', error: 'consultaNoValidada' } }));
    }
    const DIDDocument = this.#objetos.get(params[0].did);
    const result = DIDDocument
      ? { status: 'success', node: { LedgerEntryType: 'DID', Account: params[0].did, DIDDocument } }
      : { status: 'error', error: 'entryNotFound' };
    return new Response(JSON.stringify({ result }));
  };

  resolutor(cacheSegundos = 0): Resolutor {
    return new Resolutor({ xrpl: new MetodoXrpl({ servidores: { '1': SERVIDOR }, fetch: this.fetch, cacheSegundos }) });
  }
}

describe('did:xrpl: forma compacta', () => {
  it('entra en el campo del ledger y solo lleva la clave pública', () => {
    const maxi = new Billetera();
    const forma = formaCompacta(maxi.clavePublica);
    assert.ok(Buffer.byteLength(forma) <= MAXIMO_CAMPO);
    const valor = JSON.parse(forma);
    assert.deepEqual(Object.keys(valor), ['vinculo', 'clave']);
    assert.match(valor.clave, /^z6Mk/);
    assert.ok(Buffer.byteLength(formaCompacta(maxi.clavePublica, 'https://buzon.example/maxi')) <= MAXIMO_CAMPO);
    assert.throws(() => formaCompacta(maxi.clavePublica, `https://${'a'.repeat(200)}.example/`), /256/);
    assert.throws(() => formaCompacta(maxi.clavePublica, 'http://buzon.example/'), /HTTPS/);
  });

  it('el resolutor arma desde el ledger el mismo documento que tendría un did:key', async () => {
    const ledger = new LedgerSimulado();
    const par = generarParEd25519();
    const maxi = new Billetera(par, { did: DID });
    ledger.publicar(CUENTA, formaCompacta(maxi.clavePublica, 'https://buzon.example/maxi'));

    const documento = await ledger.resolutor().resolver(DID);
    assert.equal(documento.id, DID);
    assert.equal(maxi.kid, `${DID}#${new Billetera(par).did.slice('did:key:'.length)}`);
    assert.deepEqual(documento.capabilityDelegation, [maxi.kid]);
    assert.deepEqual(documento.assertionMethod, [maxi.kid]);
    assert.match(documento.keyAgreement?.[0] ?? '', new RegExp(`^${DID}#z6LS`));
    assert.deepEqual(buzonesDe(documento), ['https://buzon.example/maxi']);
  });

  it('una delegación se verifica con la clave del ledger; firmada con otra, no; y la clave se puede rotar', async () => {
    const ledger = new LedgerSimulado();
    const maxi = new Billetera(undefined, { did: DID });
    ledger.publicar(CUENTA, formaCompacta(maxi.clavePublica));
    const agente = new Billetera().did;
    const ahora = ahoraEnSegundos();

    const jwt = maxi.delegar(agente, { agente: claude, alcance: [ALCANCE.leerBuzon] });
    const delegacion = await verificarDelegacion(jwt, ledger.resolutor(), { ahora, emisor: DID, agente, alcance: ALCANCE.leerBuzon });
    assert.equal(delegacion.iss, DID);

    const impostor = new Billetera(undefined, { did: DID });
    await assert.rejects(verificarDelegacion(impostor.delegar(agente, { agente: claude, alcance: [] }), ledger.resolutor(), { ahora }), /no está autorizada/);

    // Maxi publica una clave nueva: el DID no cambia y lo firmado con la anterior deja de valer.
    const nueva = new Billetera(undefined, { did: DID });
    ledger.publicar(CUENTA, formaCompacta(nueva.clavePublica));
    await assert.rejects(verificarDelegacion(jwt, ledger.resolutor(), { ahora }), /no está autorizada/);
    await verificarDelegacion(nueva.delegar(agente, { agente: claude, alcance: [] }), ledger.resolutor(), { ahora, emisor: DID });
  });

  it('rechaza versiones desconocidas, JSON inválido, redes sin servidor y cuentas sin registro', async () => {
    const ledger = new LedgerSimulado();
    const otra = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';
    const tercera = 'rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn';
    ledger.publicar(otra, JSON.stringify({ vinculo: 2, clave: JSON.parse(formaCompacta(new Billetera().clavePublica)).clave }));
    ledger.publicar(tercera, 'no es JSON');
    const resolutor = ledger.resolutor();
    await assert.rejects(resolutor.resolver(didXrpl(1, otra)), /versión/);
    await assert.rejects(resolutor.resolver(didXrpl(1, tercera)), /JSON/);
    await assert.rejects(resolutor.resolver(DID), /no está registrado/);
    await assert.rejects(resolutor.resolver(didXrpl(0, CUENTA)), /no hay servidor configurado para la red XRPL 0/);
    assert.throws(() => didXrpl('uno', CUENTA), /inválida/);
  });

  it('guarda lo resuelto un rato para no consultar el ledger en cada mensaje', async () => {
    const ledger = new LedgerSimulado();
    ledger.publicar(CUENTA, formaCompacta(new Billetera().clavePublica));
    const conCache = ledger.resolutor(60);
    await conCache.resolver(DID);
    await conCache.resolver(DID);
    assert.equal(ledger.consultas, 1);
    const sinCache = ledger.resolutor(0);
    await sinCache.resolver(DID);
    await sinCache.resolver(DID);
    assert.equal(ledger.consultas, 3);
  });

  it('lo guardado tiene un máximo: cuando se llena, se van los documentos más viejos', async () => {
    const ledger = new LedgerSimulado();
    const cuentas = [CUENTA, 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', 'rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn'];
    for (const cuenta of cuentas) ledger.publicar(cuenta, formaCompacta(new Billetera().clavePublica));
    const metodo = new MetodoXrpl({ servidores: { '1': SERVIDOR }, fetch: ledger.fetch, cacheMaximo: 2 });
    const resolutor = new Resolutor({ xrpl: metodo });

    for (const cuenta of cuentas) await resolutor.resolver(didXrpl(1, cuenta));
    assert.equal(metodo.enCache, 2);
    assert.equal(ledger.consultas, 3);
    await resolutor.resolver(didXrpl(1, cuentas[2]));
    assert.equal(ledger.consultas, 3, 'el último sigue guardado');
    await resolutor.resolver(didXrpl(1, cuentas[0]));
    assert.equal(ledger.consultas, 4, 'el primero se había ido y se vuelve a leer');
    assert.equal(metodo.enCache, 2);
  });
});

describe('did:xrpl de punta a punta', () => {
  it('mamá y Maxi se escriben con la identidad de Maxi en el ledger; un impostor con su DID queda afuera', async () => {
    const ledger = new LedgerSimulado();
    const resolutor = ledger.resolutor(60);
    const servidor = new ServidorBuzon({ resolutor });
    const buzon = await servidor.iniciar();
    try {
      const maxi = new Billetera(undefined, { did: DID });
      ledger.publicar(CUENTA, formaCompacta(maxi.clavePublica));
      const mama = new Billetera();
      const agendaMaxi = new Agenda();
      agendaMaxi.agregar({ did: mama.did, nombre: 'Mamá', alias: ['madre'], buzon, verificadoEnPersona: true, permisos: { llamar: true } });
      const agendaMama = new Agenda();
      agendaMama.agregar({ did: DID, nombre: 'Maxi', alias: ['hijo'], buzon, verificadoEnPersona: true, permisos: { llamar: true } });
      const deMaxi = new Agente({ datos: claude, billetera: maxi, buzon, resolutor, agenda: agendaMaxi });
      const deMama = new Agente({ datos: { nombre: 'Gemini', proveedor: 'Google', procesamiento: 'nube' }, billetera: mama, buzon, resolutor, agenda: agendaMama });

      await deMaxi.enviar(agendaMaxi.buscar('madre')!, TIPOS.texto, { texto: 'llego a las 8' });
      const [recibido] = await deMama.revisarBuzon();
      assert.deepEqual([recibido.bandeja, recibido.motivo], ['principal', undefined]);
      assert.equal(recibido.mensaje?.from, DID);

      // El sobre de mamá se cifra para la clave de acuerdo que sale del ledger.
      await deMama.enviar(agendaMama.buscar('hijo')!, TIPOS.texto, { texto: 'te espero' });
      const [respuesta] = await deMaxi.revisarBuzon();
      assert.deepEqual([respuesta.bandeja, respuesta.motivo], ['principal', undefined]);

      const impostor = new Agente({ datos: claude, billetera: new Billetera(undefined, { did: DID }), buzon, resolutor, agenda: agendaMaxi });
      await impostor.enviar({ did: mama.did, buzon }, TIPOS.texto, { texto: 'soy Maxi, mandame la clave del banco' });
      const [falso] = await deMama.revisarBuzon();
      assert.equal(falso.bandeja, 'rechazados');
      assert.match(falso.motivo ?? '', /no está autorizada/);
      // Tampoco puede leer el buzón de Maxi: el buzón verifica la delegación contra el ledger.
      await assert.rejects(impostor.revisarBuzon(), /403/);
    } finally {
      await servidor.detener();
    }
  });

  it('si Maxi registró su identidad, el complemento y la agenda de mamá usan el did:xrpl, con la misma clave', () => {
    const carpeta = mkdtempSync(join(tmpdir(), 'vinculo-xrpl-'));
    const opciones = { carpeta, buzon: 'http://127.0.0.1:9' };
    try {
      const antes = cargarIdentidades(opciones);
      assert.match(antes.maxi.billetera.did, /^did:key:/);
      assert.equal(antes.xrpl, undefined);

      // Cuenta creada pero DIDSet sin confirmar: sigue con did:key.
      guardarRegistroXrpl(carpeta, { version: 1, aviso: 'prueba', red: '1', semilla: 'sEdPrueba', cuenta: CUENTA });
      assert.match(cargarIdentidades(opciones).maxi.billetera.did, /^did:key:/);

      guardarRegistroXrpl(carpeta, { version: 1, aviso: 'prueba', red: '1', semilla: 'sEdPrueba', cuenta: CUENTA, did: DID, transaccion: 'ABC' });
      const despues = cargarIdentidades(opciones);
      assert.equal(despues.maxi.billetera.did, DID);
      assert.equal(despues.mama.agenda.buscar('hijo')?.did, DID);
      assert.deepEqual(despues.maxi.billetera.clavePublica, antes.maxi.billetera.clavePublica);
      assert.deepEqual(despues.xrpl, { did: DID, cuenta: CUENTA, red: '1', transaccion: 'ABC' });
    } finally {
      rmSync(carpeta, { recursive: true, force: true });
    }
  });
});
