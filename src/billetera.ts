// Billetera de identidad: vive en el dispositivo de la persona y guarda sus claves.
// Delega en agentes, revoca delegaciones y descifra los sobres dirigidos a la persona.
// Ningún agente recibe nunca la clave privada de la persona.
import { randomUUID, type KeyObject, type webcrypto } from 'node:crypto';
import { generarParEd25519, parEd25519DesdeSemilla, semillaEd25519, x25519PrivadaDesdeEd25519, type ParEd25519 } from './cripto/claves.ts';
import { didKeyDesdeEd25519, documentoDeUnaClave } from './did/clave.ts';
import { MULTICODEC_ED25519, claveDeAcuerdo, multibaseDeClave } from './did/documento.ts';
import {
  ALCANCE,
  TIPO_DELEGACION,
  TIPO_REVOCACIONES,
  validarDatosAgente,
  type DatosAgente,
  type Delegacion,
  type ListaRevocaciones,
} from './delegacion.ts';
import { ahoraEnSegundos, comprobarVigencia, firmarJws, verificarJws } from './jose.ts';
import { descifrar } from './sobre.ts';

export interface OpcionesBilletera {
  /**
   * DID de la persona, si no es el did:key de su clave. Por ejemplo, un did:xrpl cuyo objeto en el ledger
   * publica esta clave en la forma compacta (sección 3.3 de SPEC.md).
   */
  did?: string;
}

export interface OpcionesDelegar {
  agente: DatosAgente;
  alcance: string[];
  /** Duración en segundos; por defecto, 30 días. */
  duracion?: number;
  ahora?: number;
}

export class Billetera {
  readonly did: string;
  readonly kid: string;
  #par: ParEd25519;
  #acuerdo: { kid: string; privada: KeyObject };
  #revocadas: string[] = [];
  #version = 0;

  constructor(par: ParEd25519 = generarParEd25519(), opciones: OpcionesBilletera = {}) {
    this.#par = par;
    this.did = opciones.did ?? didKeyDesdeEd25519(par.publicaCruda);
    // El mismo documento que publica el DID: con did:key sale de la clave; con did:xrpl, del ledger.
    const documento = documentoDeUnaClave(this.did, multibaseDeClave(MULTICODEC_ED25519, par.publicaCruda));
    this.kid = documento.assertionMethod![0];
    this.#acuerdo = {
      kid: claveDeAcuerdo(documento).kid,
      privada: x25519PrivadaDesdeEd25519(semillaEd25519(par.privada)),
    };
  }

  static desdeSemilla(semilla: Uint8Array, opciones: OpcionesBilletera = {}): Billetera {
    return new Billetera(parEd25519DesdeSemilla(semilla), opciones);
  }

  /** Clave pública Ed25519 de la persona (32 bytes): la que se publica, por ejemplo, en el ledger. */
  get clavePublica(): Uint8Array {
    return Uint8Array.from(this.#par.publicaCruda);
  }

  /** Clave pública en JWK, para ligar credenciales a esta persona (claim `cnf`). */
  get jwkPublica(): webcrypto.JsonWebKey {
    return this.#par.publica.export({ format: 'jwk' });
  }

  firmar(cabecera: { typ: string }, carga: unknown): string {
    return firmarJws({ alg: 'EdDSA', typ: cabecera.typ, kid: this.kid }, carga, this.#par.privada);
  }

  delegar(agente: string, opciones: OpcionesDelegar): string {
    validarDatosAgente(opciones.agente);
    const ahora = opciones.ahora ?? ahoraEnSegundos();
    const carga: Delegacion = {
      iss: this.did,
      sub: agente,
      jti: randomUUID(),
      iat: ahora,
      nbf: ahora,
      exp: ahora + (opciones.duracion ?? 30 * 24 * 3600),
      alcance: [...opciones.alcance],
      agente: opciones.agente,
    };
    return this.firmar({ typ: TIPO_DELEGACION }, carga);
  }

  /** Revoca una delegación y devuelve la lista firmada para publicar en el buzón. */
  revocar(jti: string, ahora = ahoraEnSegundos()): string {
    if (!this.#revocadas.includes(jti)) this.#revocadas.push(jti);
    this.#version += 1;
    const lista: ListaRevocaciones = { iss: this.did, iat: ahora, version: this.#version, revocadas: [...this.#revocadas] };
    return this.firmar({ typ: TIPO_REVOCACIONES }, lista);
  }

  /**
   * Descifra un sobre dirigido a la persona, solo para un agente con una delegación vigente que incluya
   * «billetera:descifrar». En un teléfono real, además, el sistema operativo autentica al proceso del agente.
   */
  descifrar(jwe: string, delegacionDelAgente: string, ahora = ahoraEnSegundos()): string {
    const { cabecera, carga } = verificarJws<Delegacion>(delegacionDelAgente, this.#par.publica);
    if (cabecera.typ !== TIPO_DELEGACION || carga.iss !== this.did) throw new Error('la delegación no fue emitida por esta billetera');
    comprobarVigencia(carga, ahora, 'delegación');
    if (!carga.alcance.includes(ALCANCE.descifrar)) throw new Error('el agente no tiene permiso para descifrar');
    if (this.#revocadas.includes(carga.jti)) throw new Error('delegación revocada por su titular');
    return descifrar(this.#acuerdo.privada, this.#acuerdo.kid, jwe);
  }
}
