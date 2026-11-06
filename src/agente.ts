// El agente: interpreta las órdenes de su persona, envía mensajes firmados con su propia clave
// (junto con la delegación que lo autoriza) y procesa lo que llega aplicando la política del receptor.
import { randomUUID } from 'node:crypto';
import type { Agenda, Contacto } from './agenda.ts';
import type { Billetera } from './billetera.ts';
import type { Cerebro } from './cerebro/tipos.ts';
import { generarParEd25519, publicaEd25519, type ParEd25519 } from './cripto/claves.ts';
import { ALCANCE, verificarDelegacion, verificarRevocaciones, type DatosAgente, type Delegacion } from './delegacion.ts';
import { didKeyDesdeEd25519, kidDeDidKey } from './did/clave.ts';
import { buzonesDe, claveDeAcuerdo, claveDeFirma } from './did/documento.ts';
import type { Resolutor } from './did/resolutor.ts';
import { ahoraEnSegundos, decodificarJws, firmarJws, verificarJws } from './jose.ts';
import { TIPOS, VIGENCIA_MAXIMA, validarMensaje, type Mensaje, type TipoMensaje } from './mensajes.ts';
import { decidir, type Decision } from './politica.ts';
import { ClienteBuzon, depositar, obtenerRevocaciones, type Firmante } from './relay/cliente.ts';
import { TIPO_MENSAJE_FIRMADO, cifrar } from './sobre.ts';
import { VistosEnMemoria, claveDeMensaje, type RegistroVistos } from './vistos.ts';

export interface Notificacion extends Decision {
  mensaje?: Mensaje;
  /** Atributos que el remitente eligió revelar con su credencial (nivel B). */
  credencial?: Record<string, unknown>;
  /** Por qué se rechazó, si se rechazó. */
  motivo?: string;
}

export interface OpcionesAgente {
  datos: DatosAgente;
  /** La billetera de la persona en este dispositivo: delega en el agente y descifra para él. */
  billetera: Billetera;
  /** Buzón propio de la persona. */
  buzon: string;
  resolutor: Resolutor;
  agenda: Agenda;
  cerebro?: Cerebro;
  alcance?: string[];
  duracion?: number;
  /** Arma una presentación de credencial (nivel B) ligada a un destinatario y a un mensaje. */
  presentarCredencial?: (destinatario: string, idMensaje: string) => string;
  /** Verifica la credencial de un remitente y devuelve lo que revela, o null si no es válida. */
  verificarCredencial?: (presentacion: string, destinatario: string, idMensaje: string) => Record<string, unknown> | null;
  /**
   * Mensajes ya procesados. Es de la persona: si se renueva el agente, el nuevo tiene que recibir el mismo
   * registro. Por defecto, uno en memoria para este agente.
   */
  vistos?: RegistroVistos;
  ahora?: () => number;
}

const ALCANCE_COMPLETO: string[] = [...Object.values(TIPOS), ALCANCE.leerBuzon, ALCANCE.descifrar];

/** El motivo de un rechazo puede citar datos del remitente: se quitan los caracteres de control y se acorta. */
const motivoSeguro = (error: unknown) =>
  String(error instanceof Error ? error.message : error)
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu, ' ')
    .slice(0, 200);

export class Agente {
  readonly did: string;
  readonly kid: string;
  readonly datos: DatosAgente;
  readonly delegacion: string;
  #par: ParEd25519;
  #o: OpcionesAgente;
  #vistos: RegistroVistos;
  /** Sobres ya procesados cuyo borrado falló: se reintenta borrarlos sin volver a mostrarlos. */
  #sinBorrar = new Set<string>();

  constructor(opciones: OpcionesAgente) {
    this.#o = opciones;
    this.#vistos = opciones.vistos ?? new VistosEnMemoria();
    this.#par = generarParEd25519();
    this.did = didKeyDesdeEd25519(this.#par.publicaCruda);
    this.kid = kidDeDidKey(this.did);
    this.datos = opciones.datos;
    // La persona autoriza al agente al instalarlo: su billetera firma la delegación.
    this.delegacion = opciones.billetera.delegar(this.did, {
      agente: opciones.datos,
      alcance: opciones.alcance ?? ALCANCE_COMPLETO,
      duracion: opciones.duracion,
      ahora: this.#ahora(),
    });
  }

  /** DID de la persona a la que representa. */
  get persona(): string {
    return this.#o.billetera.did;
  }

  get jtiDelegacion(): string {
    return decodificarJws<Delegacion>(this.delegacion).carga.jti;
  }

  async ordenar(orden: string): Promise<string> {
    if (!this.#o.cerebro) throw new Error('este agente no tiene un cerebro configurado');
    const nombres = this.#o.agenda.todos.flatMap((c) => [c.nombre, ...c.alias]);
    const intencion = await this.#o.cerebro.interpretar(orden, nombres);
    switch (intencion.accion) {
      case 'texto': {
        const contacto = this.#contacto(intencion.contacto);
        await this.enviar(contacto, TIPOS.texto, { texto: intencion.texto });
        return `${this.datos.nombre}: le escribí a ${contacto.nombre} «${intencion.texto}».`;
      }
      case 'llamar': {
        const contacto = this.#contacto(intencion.contacto);
        await this.enviar(contacto, TIPOS.solicitudLlamada, { modo: intencion.modo, urgencia: 'normal' });
        return `${this.datos.nombre}: le pedí a ${contacto.nombre} una ${intencion.modo === 'video' ? 'videollamada' : 'llamada de voz'}.`;
      }
      case 'desconocida':
        return `${this.datos.nombre}: no pude cumplir la orden (${intencion.motivo}).`;
    }
  }

  #contacto(texto: string): Contacto {
    const contacto = this.#o.agenda.buscar(texto);
    if (!contacto) throw new Error(`«${texto}» no está en la agenda`);
    return contacto;
  }

  async enviar(
    destino: { did: string; buzon: string },
    tipo: TipoMensaje,
    cuerpo: Record<string, unknown>,
    opciones: { conCredencial?: boolean } = {},
  ): Promise<string> {
    const ahora = this.#ahora();
    const mensaje: Mensaje = {
      id: randomUUID(),
      type: tipo,
      from: this.persona,
      to: [destino.did],
      created_time: ahora,
      expires_time: ahora + VIGENCIA_MAXIMA,
      body: cuerpo,
      delegation: this.delegacion,
      reply_to: this.#o.buzon,
    };
    if (opciones.conCredencial) {
      if (!this.#o.presentarCredencial) throw new Error('este agente no tiene una credencial para presentar');
      mensaje.presentation = this.#o.presentarCredencial(destino.did, mensaje.id);
    }
    validarMensaje(mensaje);
    const firmado = firmarJws({ alg: 'EdDSA', typ: TIPO_MENSAJE_FIRMADO, kid: this.kid }, mensaje, this.#par.privada);
    const acuerdo = claveDeAcuerdo(await this.#o.resolutor.resolver(destino.did));
    await depositar(destino.buzon, destino.did, cifrar(acuerdo, firmado));
    return mensaje.id;
  }

  async revisarBuzon(): Promise<Notificacion[]> {
    const cliente = new ClienteBuzon(this.#o.buzon, this.persona, this.#firmante());
    const notificaciones: Notificacion[] = [];
    for (const sobre of await cliente.retirar()) {
      if (!this.#sinBorrar.has(sobre.id)) notificaciones.push(await this.#procesar(sobre.jwe));
      try {
        await cliente.borrar(sobre.id);
        this.#sinBorrar.delete(sobre.id);
      } catch {
        // El mensaje ya se procesó y se entrega igual; el borrado se reintenta en la próxima revisión.
        this.#sinBorrar.add(sobre.id);
      }
    }
    return notificaciones;
  }

  #firmante(): Firmante {
    return {
      did: this.did,
      delegacion: this.delegacion,
      firmar: (cabecera, carga) => firmarJws({ alg: 'EdDSA', typ: cabecera.typ, kid: this.kid }, carga, this.#par.privada),
    };
  }

  async #procesar(jwe: string): Promise<Notificacion> {
    try {
      const ahora = this.#ahora();
      const firmado = this.#o.billetera.descifrar(jwe, this.delegacion, ahora);

      // 1. Firma del agente remitente.
      const { cabecera, carga } = decodificarJws<unknown>(firmado);
      if (cabecera.typ !== TIPO_MENSAJE_FIRMADO || !cabecera.kid) throw new Error('el contenido no es un mensaje Vínculo firmado');
      const agenteRemitente = cabecera.kid.split('#')[0];
      const documento = await this.#o.resolutor.resolver(agenteRemitente);
      verificarJws(firmado, publicaEd25519(claveDeFirma(documento, cabecera.kid, 'assertionMethod')));

      // 2. Forma, destino, frescura y repetición.
      validarMensaje(carga);
      const mensaje = carga;
      if (!mensaje.to.includes(this.persona)) throw new Error('el mensaje no está dirigido a esta persona');
      if (mensaje.expires_time < ahora) throw new Error('el mensaje venció');
      if (mensaje.created_time > ahora + 300) throw new Error('el mensaje tiene fecha futura');
      const clave = claveDeMensaje(mensaje.from, mensaje.id);
      if (this.#vistos.visto(clave, ahora)) throw new Error('mensaje repetido');

      // 3. Delegación: la persona que figura como remitente autorizó a ese agente, para ese tipo de mensaje.
      const revocaciones = await this.#revocacionesDe(mensaje.from);
      const delegacion = await verificarDelegacion(mensaje.delegation, this.#o.resolutor, {
        ahora,
        emisor: mensaje.from,
        agente: agenteRemitente,
        alcance: mensaje.type,
        revocadas: revocaciones.revocadas,
      });
      // Se anota recién verificado; si otra revisión lo anotó mientras tanto, es una repetición.
      if (!this.#vistos.anotar(clave, mensaje.expires_time, ahora)) throw new Error('mensaje repetido');

      // 4. Credencial opcional (nivel B), ligada a este destinatario y a este mensaje.
      const credencial =
        mensaje.presentation && this.#o.verificarCredencial
          ? this.#o.verificarCredencial(mensaje.presentation, this.persona, mensaje.id)
          : null;

      // 5. Política: decide la bandeja; nunca ejecuta el contenido.
      const decision = decidir({ mensaje, delegacion, humanoVerificado: credencial?.persona_verificada === true }, this.#o.agenda);
      if (!revocaciones.comprobadas) {
        decision.avisos.push('No se pudo comprobar si quien escribe revocó a este agente: no publica su buzón.');
      }
      return { ...decision, mensaje, ...(credencial ? { credencial } : {}) };
    } catch (error) {
      return { bandeja: 'rechazados', accion: 'descartar', resumen: 'Mensaje rechazado', avisos: [], motivo: motivoSeguro(error) };
    }
  }

  /**
   * Revocaciones de una persona, leídas de su buzón: el de la agenda o, si no es un contacto, el que publica su
   * documento DID. Nunca el reply_to del mensaje, que elige quien escribe (SPEC, sección 4.3). Si no hay buzón
   * conocido, no se pueden comprobar: el mensaje solo llega como solicitud, con un aviso.
   */
  async #revocacionesDe(persona: string): Promise<{ revocadas: Set<string>; comprobadas: boolean }> {
    const buzon = this.#o.agenda.porDid(persona)?.buzon ?? buzonesDe(await this.#o.resolutor.resolver(persona))[0];
    if (!buzon) return { revocadas: new Set(), comprobadas: false };
    const jwt = await obtenerRevocaciones(buzon, persona);
    if (!jwt) return { revocadas: new Set(), comprobadas: true };
    return { revocadas: new Set((await verificarRevocaciones(jwt, this.#o.resolutor, persona)).revocadas), comprobadas: true };
  }

  #ahora(): number {
    return this.#o.ahora ? this.#o.ahora() : ahoraEnSegundos();
  }
}
