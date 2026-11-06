import assert from 'node:assert/strict';
import { createPublicKey, diffieHellman, randomBytes, sign } from 'node:crypto';
import { describe, it } from 'node:test';
import { aBase58btc, aBase64url, deBase58btc } from '../src/codec.ts';
import {
  crudaDePublica,
  generarParEd25519,
  parEd25519DesdeSemilla,
  privadaX25519,
  publicaX25519,
  semillaEd25519,
  x25519PrivadaDesdeEd25519,
  x25519PublicaDesdeEd25519,
} from '../src/cripto/claves.ts';
import { cifrar, concatKdf, descifrar, leerCabeceraSobre } from '../src/sobre.ts';

const hex = (texto: string) => Buffer.from(texto.replace(/\s+/g, ''), 'hex');

describe('codificaciones', () => {
  it('base58btc coincide con el vector conocido y conserva ceros iniciales', () => {
    assert.equal(aBase58btc(Buffer.from('Hello World!')), '2NEpo7TZRRrLZSi2U');
    const datos = Uint8Array.from([0, 0, ...randomBytes(30)]);
    assert.deepEqual(deBase58btc(aBase58btc(datos)), datos);
  });
});

describe('claves', () => {
  it('reproduce el vector TEST 1 de Ed25519 (RFC 8032, sección 7.1)', () => {
    const par = parEd25519DesdeSemilla(hex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'));
    assert.equal(Buffer.from(par.publicaCruda).toString('hex'), 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    assert.equal(
      sign(null, Buffer.alloc(0), par.privada).toString('hex'),
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
    );
  });

  it('reproduce el acuerdo X25519 del ejemplo A.6 (RFC 8037)', () => {
    const efimera = privadaX25519(hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'));
    assert.equal(
      Buffer.from(crudaDePublica(createPublicKey(efimera))).toString('hex'),
      '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
    );
    const z = diffieHellman({ privateKey: efimera, publicKey: publicaX25519(hex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')) });
    assert.equal(z.toString('hex'), '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');
  });

  it('la clave X25519 derivada de Ed25519 es la misma por los dos caminos', () => {
    for (let i = 0; i < 20; i++) {
      const par = generarParEd25519();
      const porMapa = x25519PublicaDesdeEd25519(par.publicaCruda);
      const porEscalar = crudaDePublica(createPublicKey(x25519PrivadaDesdeEd25519(semillaEd25519(par.privada))));
      assert.deepEqual(Buffer.from(porMapa), Buffer.from(porEscalar));
    }
  });
});

describe('sobre cifrado (JWE)', () => {
  it('Concat KDF reproduce el ejemplo del apéndice C de RFC 7518', () => {
    const z = Uint8Array.from([
      158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140,
      254, 144, 196,
    ]);
    const clave = concatKdf(z, 'A128GCM', 128, Buffer.from('Alice'), Buffer.from('Bob'));
    assert.equal(aBase64url(clave), 'VqqN6vgjbSBcIijNcacQGg');
  });

  function destinatario(nombre = 'ana') {
    const par = generarParEd25519();
    return {
      kid: `did:ejemplo:${nombre}#acuerdo`,
      publica: x25519PublicaDesdeEd25519(par.publicaCruda),
      privada: x25519PrivadaDesdeEd25519(semillaEd25519(par.privada)),
    };
  }

  it('cifra y descifra, y la cabecera no revela al remitente', () => {
    const ana = destinatario();
    const jwe = cifrar(ana, 'hola, ¿llegás a las 8?');
    assert.equal(descifrar(ana.privada, ana.kid, jwe), 'hola, ¿llegás a las 8?');
    const cabecera = leerCabeceraSobre(jwe);
    assert.equal(cabecera.alg, 'ECDH-ES');
    assert.equal(cabecera.enc, 'A256GCM');
    assert.deepEqual(Object.keys(cabecera).sort(), ['alg', 'cty', 'enc', 'epk', 'kid', 'typ']);
  });

  it('no se puede descifrar con otra clave', () => {
    const ana = destinatario();
    const intruso = destinatario('intruso');
    const jwe = cifrar(ana, 'secreto');
    assert.throws(() => descifrar(intruso.privada, ana.kid, jwe), /alterado|clave no corresponde/);
    assert.throws(() => descifrar(ana.privada, intruso.kid, jwe), /no está dirigido/);
  });

  it('detecta alteraciones del texto cifrado y de la cabecera', () => {
    const ana = destinatario();
    const partes = cifrar(ana, 'secreto').split('.');
    const texto = Buffer.from(partes[3], 'base64url');
    texto[0] ^= 1;
    assert.throws(() => descifrar(ana.privada, ana.kid, [partes[0], '', partes[2], texto.toString('base64url'), partes[4]].join('.')));
    const cabecera = JSON.parse(Buffer.from(partes[0], 'base64url').toString());
    cabecera.cty = 'otra-cosa';
    const otraCabecera = Buffer.from(JSON.stringify(cabecera)).toString('base64url');
    assert.throws(() => descifrar(ana.privada, ana.kid, [otraCabecera, '', partes[2], partes[3], partes[4]].join('.')));
  });
});
