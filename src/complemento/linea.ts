// La «línea» Vínculo de una persona, tal como la usa un complemento de IA: escribir, revisar y llamar.
// La IA nunca toca las claves: pide acciones y recibe resultados. Por dentro, cada acción la hace un
// agente con clave propia y una delegación firmada por la billetera de la persona.
import type { Agenda, Contacto } from '../agenda.ts';
import { Agente, type Notificacion } from '../agente.ts';
import type { Billetera } from '../billetera.ts';
import type { DatosAgente, Delegacion } from '../delegacion.ts';
import type { Resolutor } from '../did/resolutor.ts';
import { ahoraEnSegundos, decodificarJws } from '../jose.ts';
import { TIPOS } from '../mensajes.ts';
import { VistosEnMemoria, type RegistroVistos } from '../vistos.ts';

export type ModoLlamada = 'voz' | 'video';

export interface OpcionesLinea {
  persona: string;
  billetera: Billetera;
  agenda: Agenda;
  /** Buzón propio de la persona. */
  buzon: string;
  resolutor: Resolutor;
  /** Quién es el agente; se consulta al crear cada delegación (el asistente se conoce recién al conectarse). */
  datosAgente: () => DatosAgente;
  /** Vigencia de cada delegación, en segundos. Por defecto, 12 horas. */
  duracionDelegacion?: number;
  /** Cada cuánto se revisa el buzón mientras se espera una respuesta, en milisegundos. */
  intervaloMs?: number;
  /** Mensajes ya vistos, compartidos por todos los agentes de la línea. Por defecto, en memoria. */
  vistos?: RegistroVistos;
}

export interface ResultadoEnvio {
  persona: string;
  agente: DatosAgente;
  contacto: Contacto;
  id: string;
}

export interface ResultadoLlamada extends ResultadoEnvio {
  modo: ModoLlamada;
  esperaSegundos: number;
  respondio: boolean;
  acepta: boolean;
}

export interface EstadoLinea {
  persona: string;
  did: string;
  agente: DatosAgente;
  didAgente: string;
  vence: number;
  alcance: string[];
  buzon: string;
}

const esperar = (ms: number) => new Promise<void>((listo) => setTimeout(listo, ms));

export class LineaVinculo {
  #o: OpcionesLinea;
  #agente: Agente | undefined;
  #vistos: RegistroVistos;
  /** Mensajes ya retirados del buzón que la persona todavía no vio. */
  #pendientes: Notificacion[] = [];

  constructor(opciones: OpcionesLinea) {
    this.#o = opciones;
    // Un solo registro para toda la línea: al renovar el agente, el nuevo recuerda lo que vio el anterior.
    this.#vistos = opciones.vistos ?? new VistosEnMemoria();
  }

  contactos(): Contacto[] {
    return this.#o.agenda.todos;
  }

  async enviarMensaje(contacto: string, texto: string): Promise<ResultadoEnvio> {
    const destino = this.#contacto(contacto);
    const agente = this.#agenteVigente();
    const id = await agente.enviar(destino, TIPOS.texto, { texto });
    return { persona: this.#o.persona, agente: agente.datos, contacto: destino, id };
  }

  /** Devuelve lo que llegó desde la última revisión y lo da por visto. */
  async revisar(): Promise<Notificacion[]> {
    await this.#traer();
    const nuevas = this.#pendientes;
    this.#pendientes = [];
    return nuevas;
  }

  /** Pide una llamada y espera la respuesta. Lo que llegue mientras tanto queda para la próxima revisión. */
  async llamar(contacto: string, modo: ModoLlamada, esperaSegundos = 20): Promise<ResultadoLlamada> {
    const destino = this.#contacto(contacto);
    const agente = this.#agenteVigente();
    const id = await agente.enviar(destino, TIPOS.solicitudLlamada, { modo, urgencia: 'normal' });
    const base = { persona: this.#o.persona, agente: agente.datos, contacto: destino, id, modo, esperaSegundos };
    const limite = Date.now() + esperaSegundos * 1000;
    for (;;) {
      await this.#traer();
      const indice = this.#pendientes.findIndex(
        (n) => n.mensaje?.type === TIPOS.respuestaLlamada && n.mensaje.from === destino.did && n.mensaje.body.en_respuesta_a === id,
      );
      if (indice >= 0) {
        const [respuesta] = this.#pendientes.splice(indice, 1);
        return { ...base, respondio: true, acepta: respuesta.mensaje!.body.acepta === true };
      }
      if (Date.now() >= limite) return { ...base, respondio: false, acepta: false };
      await esperar(this.#o.intervaloMs ?? 1000);
    }
  }

  estado(): EstadoLinea {
    const agente = this.#agenteVigente();
    const delegacion = decodificarJws<Delegacion>(agente.delegacion).carga;
    return {
      persona: this.#o.persona,
      did: this.#o.billetera.did,
      agente: agente.datos,
      didAgente: agente.did,
      vence: delegacion.exp,
      alcance: delegacion.alcance,
      buzon: this.#o.buzon,
    };
  }

  async #traer(): Promise<void> {
    this.#pendientes.push(...(await this.#agenteVigente().revisarBuzon()));
  }

  #contacto(texto: string): Contacto {
    const contacto = this.#o.agenda.buscar(texto);
    if (contacto) return contacto;
    const nombres = this.#o.agenda.todos.map((c) => c.nombre).join(', ') || 'ninguno';
    throw new Error(`«${texto}» no está en la agenda de Vínculo de ${this.#o.persona} (contactos: ${nombres})`);
  }

  /** El agente actual; si su delegación vence en menos de un minuto, la billetera delega en uno nuevo. */
  #agenteVigente(): Agente {
    const vence = this.#agente ? decodificarJws<Delegacion>(this.#agente.delegacion).carga.exp : 0;
    if (!this.#agente || vence - 60 < ahoraEnSegundos()) {
      this.#agente = new Agente({
        datos: this.#o.datosAgente(),
        billetera: this.#o.billetera,
        buzon: this.#o.buzon,
        resolutor: this.#o.resolutor,
        agenda: this.#o.agenda,
        duracion: this.#o.duracionDelegacion ?? 12 * 3600,
        vistos: this.#vistos,
      });
    }
    return this.#agente;
  }
}
