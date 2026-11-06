import assert from 'node:assert/strict';
import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { Billetera } from '../src/billetera.ts';
import { ALCANCE, verificarDelegacion } from '../src/delegacion.ts';
import { documentoDidKey } from '../src/did/clave.ts';
import { MetodoWeb, Resolutor } from '../src/did/resolutor.ts';
import { MetodoXrpl } from '../src/did/xrpl.ts';
import { firmanteDeClave, firmarVinculacion, verificarVinculacion } from '../src/identidad/nivel-a.ts';
import { EmisorSimulado, presentar, verificarPresentacion } from '../src/identidad/nivel-b.ts';
import { ahoraEnSegundos } from '../src/jose.ts';
import { crearTarjeta, leerTarjeta } from '../src/tarjeta.ts';

const fixture = (nombre: string) => readFileSync(new URL(`../fixtures/ca-simulada/${nombre}`, import.meta.url), 'utf8');
const resolutor = new Resolutor();
const agenteGenerico = { nombre: 'Claude', proveedor: 'Anthropic', procesamiento: 'nube' as const };

describe('did:key', () => {
  it('publica una clave de firma y una de acuerdo derivada', () => {
    const { did } = new Billetera();
    const doc = documentoDidKey(did);
    assert.match(did, /^did:key:z6Mk/);
    assert.equal(doc.verificationMethod?.length, 2);
    assert.match(doc.keyAgreement?.[0] ?? '', /#z6LS/);
  });

  it('rechaza DIDs mal formados o de métodos no configurados', async () => {
    await assert.rejects(resolutor.resolver('did:key:zNoEsBase58Valido0OIl'), /base58|clave/);
    await assert.rejects(resolutor.resolver('did:ejemplo:123'), /no soportado/);
    await assert.rejects(resolutor.resolver('nada'), /mal formado/);
  });

  it('did:web arma la URL del documento', () => {
    assert.equal(MetodoWeb.url('did:web:id-uruguay.example'), 'https://id-uruguay.example/.well-known/did.json');
    assert.equal(MetodoWeb.url('did:web:ejemplo.uy:personas:ana'), 'https://ejemplo.uy/personas/ana/did.json');
  });
});

describe('did:xrpl (perfil Vínculo)', () => {
  const cuenta = 'rpfqJrXg5uidNo2ZsRhRY6TiF1cvYmV9Fg';
  const did = `did:xrpl:1:${cuenta}`;
  const servidor = 'https://xrpl.example/';
  const urlDocumento = 'https://identidad.example/ana/did.json';

  function fetchSimulado(documento: string, data: string, error?: string): typeof fetch {
    return (async (entrada: string | URL | Request) => {
      const url = String(entrada);
      if (url === servidor) {
        const result = error
          ? { status: 'error', error }
          : {
              status: 'success',
              node: {
                LedgerEntryType: 'DID',
                Account: cuenta,
                URI: Buffer.from(urlDocumento).toString('hex').toUpperCase(),
                Data: Buffer.from(data).toString('hex').toUpperCase(),
              },
            };
        return new Response(JSON.stringify({ result }));
      }
      if (url === urlDocumento) return new Response(documento);
      return new Response('', { status: 404 });
    }) as typeof fetch;
  }

  it('resuelve el documento y verifica el hash anclado en el ledger', async () => {
    const base = documentoDidKey(new Billetera().did);
    const documento = JSON.stringify({ ...base, id: did, verificationMethod: base.verificationMethod?.map((m) => ({ ...m, controller: did })) });
    const hash = `sha256:${createHash('sha256').update(documento).digest('hex')}`;
    const xrpl = new Resolutor({ xrpl: new MetodoXrpl({ servidores: { '1': servidor }, fetch: fetchSimulado(documento, hash) }) });
    const resuelto = await xrpl.resolver(did);
    assert.equal(resuelto.id, did);
  });

  it('rechaza un documento alterado fuera de la cadena', async () => {
    const documento = JSON.stringify({ id: did });
    const xrpl = new Resolutor({ xrpl: new MetodoXrpl({ servidores: { '1': servidor }, fetch: fetchSimulado(documento, 'sha256:' + '0'.repeat(64)) }) });
    await assert.rejects(xrpl.resolver(did), /hash anclado/);
  });

  it('informa cuando el DID no está registrado', async () => {
    const xrpl = new Resolutor({ xrpl: new MetodoXrpl({ servidores: { '1': servidor }, fetch: fetchSimulado('', '', 'entryNotFound') }) });
    await assert.rejects(xrpl.resolver(did), /no está registrado/);
  });
});

describe('delegación', () => {
  it('verifica una delegación vigente', async () => {
    const maxi = new Billetera();
    const agente = new Billetera().did;
    const jwt = maxi.delegar(agente, { agente: agenteGenerico, alcance: [ALCANCE.leerBuzon] });
    const d = await verificarDelegacion(jwt, resolutor, { ahora: ahoraEnSegundos(), emisor: maxi.did, agente, alcance: ALCANCE.leerBuzon });
    assert.equal(d.agente.proveedor, 'Anthropic');
  });

  it('rechaza agente equivocado, alcance faltante, vencimiento y revocación', async () => {
    const maxi = new Billetera();
    const agente = new Billetera().did;
    const ahora = ahoraEnSegundos();
    const jwt = maxi.delegar(agente, { agente: agenteGenerico, alcance: ['vinculo/texto/1.0'], duracion: 3600, ahora });
    await assert.rejects(verificarDelegacion(jwt, resolutor, { ahora, agente: new Billetera().did }), /otro agente/);
    await assert.rejects(verificarDelegacion(jwt, resolutor, { ahora, alcance: ALCANCE.leerBuzon }), /no incluye/);
    await assert.rejects(verificarDelegacion(jwt, resolutor, { ahora: ahora + 7200 }), /venció/);
    const { jti } = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
    await assert.rejects(verificarDelegacion(jwt, resolutor, { ahora, revocadas: new Set([jti]) }), /revocada/);
  });

  it('nadie puede emitir una delegación en nombre de otra persona', async () => {
    const maxi = new Billetera();
    const impostor = new Billetera();
    const agente = new Billetera().did;
    const legitima = maxi.delegar(agente, { agente: agenteGenerico, alcance: [] });
    const [cabecera, , ] = legitima.split('.');
    const falsa = impostor.delegar(agente, { agente: agenteGenerico, alcance: [] }).split('.');
    // Cabecera de Maxi con firma del impostor: no valida.
    await assert.rejects(verificarDelegacion(`${cabecera}.${falsa[1]}.${falsa[2]}`, resolutor, { ahora: ahoraEnSegundos() }));
  });
});

describe('tarjeta de contacto', () => {
  it('se verifica con el DID de su titular y detecta alteraciones', async () => {
    const mama = new Billetera();
    const tarjeta = crearTarjeta(mama, { nombre: 'Mamá', buzon: 'http://127.0.0.1:9/' });
    assert.equal((await leerTarjeta(tarjeta, resolutor)).nombre, 'Mamá');
    const [h, p, f] = tarjeta.split('.');
    const carga = JSON.parse(Buffer.from(p, 'base64url').toString());
    carga.buzon = 'http://buzon-del-atacante.example/';
    await assert.rejects(leerTarjeta(`${h}.${Buffer.from(JSON.stringify(carga)).toString('base64url')}.${f}`, resolutor), /firma/);
  });
});

describe('nivel A: vinculación con el documento de identidad', () => {
  const raiz = new X509Certificate(fixture('raiz.pem'));
  const documento = firmanteDeClave([fixture('maxi.pem'), fixture('intermedia.pem')], createPrivateKey(fixture('maxi.key')));
  const crls = [fixture('raiz.crl'), fixture('intermedia.crl')];

  it('verifica la cadena hasta la raíz y devuelve al titular', () => {
    const { did } = new Billetera();
    const resultado = verificarVinculacion(firmarVinculacion(documento, did), [raiz], { crls, did });
    assert.equal(resultado.titular.nombre, 'MAXI EJEMPLO (PRUEBA)');
    assert.equal(resultado.titular.documento, 'DNI-12345672');
    assert.equal(resultado.titular.pais, 'UY');
    assert.match(resultado.emisor, /Documentos \(SIMULADA\)/);
  });

  it('rechaza una raíz impostora con el mismo nombre', () => {
    const { did } = new Billetera();
    const impostora = new X509Certificate(fixture('raiz-impostora.pem'));
    assert.equal(impostora.subject, raiz.subject);
    assert.throws(() => verificarVinculacion(firmarVinculacion(documento, did), [impostora], { crls }), /raíz de confianza/);
  });

  it('rechaza otro DID, firmas alteradas y certificados vencidos', () => {
    const { did } = new Billetera();
    const jws = firmarVinculacion(documento, did);
    assert.throws(() => verificarVinculacion(jws, [raiz], { crls, did: new Billetera().did }), /otro DID/);
    const [h, , f] = jws.split('.');
    const otra = Buffer.from(JSON.stringify({ did: new Billetera().did, iat: ahoraEnSegundos(), declaracion: 'x' })).toString('base64url');
    assert.throws(() => verificarVinculacion(`${h}.${otra}.${f}`, [raiz], { crls }), /firma inválida/);
    const en2040 = Math.floor(Date.UTC(2040, 0, 1) / 1000);
    assert.throws(() => verificarVinculacion(jws, [raiz], { crls, ahora: en2040 }), /fuera de vigencia/);
  });

  it('rechaza una cadena incompleta', () => {
    const soloTitular = firmanteDeClave([fixture('maxi.pem')], createPrivateKey(fixture('maxi.key')));
    assert.throws(() => verificarVinculacion(firmarVinculacion(soloTitular, new Billetera().did), [raiz], { crls }), /raíz de confianza/);
  });

  it('rechaza un certificado revocado por su autoridad', () => {
    const marta = firmanteDeClave([fixture('marta.pem'), fixture('intermedia.pem')], createPrivateKey(fixture('marta.key')));
    assert.throws(
      () => verificarVinculacion(firmarVinculacion(marta, new Billetera().did), [raiz], { crls }),
      /el certificado de «MARTA EJEMPLO \(PRUEBA\)» fue revocado/,
    );
  });

  it('exige una lista de revocación vigente y firmada de cada autoridad', () => {
    const jws = firmarVinculacion(documento, new Billetera().did);
    assert.throws(() => verificarVinculacion(jws, [raiz], { crls: [fixture('intermedia.crl')] }), /falta la lista de revocación de «Autoridad Certificadora Raiz/);
    assert.throws(
      () => verificarVinculacion(jws, [raiz], { crls: [fixture('raiz.crl'), fixture('intermedia-vencida.crl')] }),
      /lista de revocación de «Autoridad Certificadora de Documentos \(SIMULADA\)» está vencida/,
    );
    // Alguien borra a Marta de la lista: la firma de la autoridad deja de valer.
    const martaRevocada = new X509Certificate(fixture('marta.pem')).serialNumber;
    const der = Buffer.from(fixture('intermedia.crl').replace(/-----(BEGIN|END) X509 CRL-----|\s+/g, ''), 'base64');
    const posicion = der.indexOf(Buffer.from(martaRevocada, 'hex'));
    assert.ok(posicion > 0);
    der[posicion + 1] ^= 0xff;
    assert.throws(
      () => verificarVinculacion(jws, [raiz], { crls: [fixture('raiz.crl'), der] }),
      /lista de revocación de «Autoridad Certificadora de Documentos \(SIMULADA\)» no está firmada por su autoridad/,
    );
  });

  it('exige el certificado de firma: el de autenticación no alcanza', () => {
    const autenticacion = firmanteDeClave(
      [fixture('maxi-autenticacion.pem'), fixture('intermedia.pem')],
      createPrivateKey(fixture('maxi-autenticacion.key')),
    );
    assert.throws(() => verificarVinculacion(firmarVinculacion(autenticacion, new Billetera().did), [raiz], { crls }), /no es de firma/);
  });
});

describe('nivel B: credencial SD-JWT con divulgación selectiva', () => {
  const estado = new EmisorSimulado('did:web:id-uruguay.example');
  const emisores = new Map([[estado.id, estado.clavePublica]]);
  const atributos = { given_name: 'Ana', family_name: 'Ejemplo', numero_documento: '3.456.789-0', mayor_de_edad: true, persona_verificada: true, nivel: 3 };
  const divulgables = ['given_name', 'family_name', 'numero_documento', 'mayor_de_edad', 'persona_verificada'];

  function credencialDe(billetera: Billetera) {
    return estado.emitir(billetera.jwkPublica, atributos, { vct: 'urn:vinculo:persona-verificada:1', divulgables });
  }

  it('revela solo lo elegido', () => {
    const ana = new Billetera();
    const p = presentar(credencialDe(ana), ['persona_verificada', 'mayor_de_edad'], ana, { aud: 'did:key:destino', nonce: 'm-1' });
    const r = verificarPresentacion(p, { emisores, aud: 'did:key:destino', nonce: 'm-1' });
    assert.deepEqual(r.atributos, { nivel: 3, mayor_de_edad: true, persona_verificada: true });
  });

  it('rechaza destinatario o mensaje distintos', () => {
    const ana = new Billetera();
    const p = presentar(credencialDe(ana), ['persona_verificada'], ana, { aud: 'did:key:destino', nonce: 'm-1' });
    assert.throws(() => verificarPresentacion(p, { emisores, aud: 'did:key:otro', nonce: 'm-1' }), /otro destinatario/);
    assert.throws(() => verificarPresentacion(p, { emisores, aud: 'did:key:destino', nonce: 'm-2' }), /otro destinatario/);
  });

  it('una credencial robada no sirve sin la clave de su dueña', () => {
    const ana = new Billetera();
    const ladron = new Billetera();
    const p = presentar(credencialDe(ana), ['persona_verificada'], ladron, { aud: 'x', nonce: 'y' });
    assert.throws(() => verificarPresentacion(p, { emisores, aud: 'x', nonce: 'y' }), /firma inválida/);
  });

  it('rechaza atributos inventados, emisores desconocidos y la falta de prueba de posesión', () => {
    const ana = new Billetera();
    const credencial = credencialDe(ana);
    const falso = Buffer.from(JSON.stringify(['sal', 'mayor_de_edad', true])).toString('base64url');
    const [jwt] = credencial.split('~');
    const inventada = presentar(`${jwt}~${falso}~`, ['mayor_de_edad'], ana, { aud: 'x', nonce: 'y' });
    assert.throws(() => verificarPresentacion(inventada, { emisores, aud: 'x', nonce: 'y' }), /no fue firmado/);
    const p = presentar(credencial, ['given_name'], ana, { aud: 'x', nonce: 'y' });
    assert.throws(() => verificarPresentacion(p, { emisores: new Map(), aud: 'x', nonce: 'y' }), /emisor no confiable/);
    assert.throws(() => verificarPresentacion(p.slice(0, p.lastIndexOf('~') + 1), { emisores, aud: 'x', nonce: 'y' }), /prueba de posesión/);
  });
});
