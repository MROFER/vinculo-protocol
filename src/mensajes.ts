// Tipos de mensaje del protocolo. El conjunto es cerrado: lo que no figura aquí se rechaza.

export const TIPOS = {
  texto: 'vinculo/texto/1.0',
  solicitudLlamada: 'vinculo/llamada/1.0/solicitud',
  respuestaLlamada: 'vinculo/llamada/1.0/respuesta',
} as const;

export type TipoMensaje = (typeof TIPOS)[keyof typeof TIPOS];

/** Vigencia máxima de un mensaje: acota cuánto tiempo hay que recordarlo para rechazar repeticiones. */
export const VIGENCIA_MAXIMA = 7 * 24 * 3600;

/** Mensaje en claro: campos de DIDComm v2 más la delegación del agente que lo envía. */
export interface Mensaje {
  id: string;
  type: TipoMensaje;
  /** DID de la persona que envía (no del agente). */
  from: string;
  /** DIDs de las personas destinatarias. */
  to: string[];
  created_time: number;
  expires_time: number;
  body: Record<string, unknown>;
  /** Delegación persona → agente que autoriza este envío. */
  delegation: string;
  /** Buzón donde responder. */
  reply_to?: string;
  /** Credencial SD-JWT presentada para este mensaje (nivel B). */
  presentation?: string;
}

const CAMPOS_MENSAJE = new Set(['id', 'type', 'from', 'to', 'created_time', 'expires_time', 'body', 'delegation', 'reply_to', 'presentation']);

const CAMPOS_CUERPO: Record<TipoMensaje, { obligatorios: string[]; opcionales: string[] }> = {
  [TIPOS.texto]: { obligatorios: ['texto'], opcionales: [] },
  [TIPOS.solicitudLlamada]: { obligatorios: ['modo'], opcionales: ['urgencia', 'nota'] },
  [TIPOS.respuestaLlamada]: { obligatorios: ['acepta', 'en_respuesta_a'], opcionales: ['nota'] },
};

export function esTipoConocido(tipo: string): tipo is TipoMensaje {
  return Object.values(TIPOS).includes(tipo as TipoMensaje);
}

function exigirTexto(valor: unknown, campo: string, maximo: number): void {
  if (typeof valor !== 'string' || valor.length === 0 || valor.length > maximo) {
    throw new Error(`el campo «${campo}» debe ser un texto de 1 a ${maximo} caracteres`);
  }
}

export function validarCuerpo(tipo: TipoMensaje, cuerpo: Record<string, unknown>): void {
  const { obligatorios, opcionales } = CAMPOS_CUERPO[tipo];
  for (const campo of Object.keys(cuerpo)) {
    if (!obligatorios.includes(campo) && !opcionales.includes(campo)) throw new Error(`campo no admitido en el cuerpo: ${campo}`);
  }
  for (const campo of obligatorios) {
    if (!(campo in cuerpo)) throw new Error(`falta el campo «${campo}»`);
  }
  switch (tipo) {
    case TIPOS.texto:
      exigirTexto(cuerpo.texto, 'texto', 4000);
      break;
    case TIPOS.solicitudLlamada:
      if (cuerpo.modo !== 'voz' && cuerpo.modo !== 'video') throw new Error('modo de llamada inválido');
      if (cuerpo.urgencia !== undefined && cuerpo.urgencia !== 'normal' && cuerpo.urgencia !== 'alta') throw new Error('urgencia inválida');
      if (cuerpo.nota !== undefined) exigirTexto(cuerpo.nota, 'nota', 500);
      break;
    case TIPOS.respuestaLlamada:
      if (typeof cuerpo.acepta !== 'boolean') throw new Error('«acepta» debe ser verdadero o falso');
      exigirTexto(cuerpo.en_respuesta_a, 'en_respuesta_a', 100);
      if (cuerpo.nota !== undefined) exigirTexto(cuerpo.nota, 'nota', 500);
      break;
  }
}

export function validarMensaje(m: unknown): asserts m is Mensaje {
  if (typeof m !== 'object' || m === null || Array.isArray(m)) throw new Error('mensaje inválido');
  const x = m as Record<string, unknown>;
  for (const campo of Object.keys(x)) {
    if (!CAMPOS_MENSAJE.has(campo)) throw new Error(`campo desconocido en el mensaje: ${campo}`);
  }
  if (typeof x.id !== 'string' || x.id.length === 0 || x.id.length > 100) throw new Error('identificador de mensaje inválido');
  if (typeof x.type !== 'string' || !esTipoConocido(x.type)) throw new Error(`tipo de mensaje no admitido: ${String(x.type)}`);
  if (typeof x.from !== 'string' || !x.from.startsWith('did:')) throw new Error('remitente inválido');
  if (!Array.isArray(x.to) || x.to.length === 0 || x.to.some((d) => typeof d !== 'string' || !d.startsWith('did:'))) {
    throw new Error('destinatarios inválidos');
  }
  if (!Number.isInteger(x.created_time) || !Number.isInteger(x.expires_time)) throw new Error('fechas inválidas');
  const vigencia = (x.expires_time as number) - (x.created_time as number);
  if (vigencia <= 0 || vigencia > VIGENCIA_MAXIMA) throw new Error('la vigencia del mensaje tiene que ser de 7 días o menos');
  if (typeof x.delegation !== 'string') throw new Error('falta la delegación del agente');
  if (x.reply_to !== undefined && (typeof x.reply_to !== 'string' || !/^https?:\/\//.test(x.reply_to))) throw new Error('reply_to inválido');
  if (x.presentation !== undefined && typeof x.presentation !== 'string') throw new Error('presentación inválida');
  if (typeof x.body !== 'object' || x.body === null || Array.isArray(x.body)) throw new Error('cuerpo inválido');
  validarCuerpo(x.type, x.body as Record<string, unknown>);
}
