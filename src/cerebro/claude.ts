// Cerebro con Claude: interpreta la orden de la persona y devuelve una acción estructurada.
// Usa el paquete opcional @anthropic-ai/sdk y las credenciales de Anthropic del entorno
// (ANTHROPIC_API_KEY o un perfil de `ant auth login`).
import type { Cerebro, Intencion } from './tipos.ts';

const ESQUEMA = {
  type: 'object',
  properties: {
    accion: { type: 'string', enum: ['texto', 'llamar', 'desconocida'] },
    contacto: { type: 'string', description: 'Nombre o alias del contacto tal como figura en la agenda; vacío si no aplica.' },
    texto: { type: 'string', description: 'El mensaje a enviar, si accion es texto; vacío si no aplica.' },
    modo: { type: 'string', enum: ['voz', 'video'] },
    motivo: { type: 'string', description: 'Por qué la orden no se puede cumplir, si accion es desconocida; vacío si no aplica.' },
  },
  required: ['accion', 'contacto', 'texto', 'modo', 'motivo'],
  additionalProperties: false,
};

const SISTEMA = [
  'Interpretás órdenes que una persona le da a su agente de mensajería.',
  'Convertí la orden en una sola acción: «texto» para enviar un mensaje, «llamar» para pedir una llamada,',
  'o «desconocida» si no es ninguna de las dos. El contacto tiene que ser uno de la agenda.',
  'En «texto», escribí el mensaje como lo diría la persona, en primera persona.',
].join(' ');

export class CerebroClaude implements Cerebro {
  readonly nombre: string;
  #modelo: string;

  constructor(modelo = 'claude-opus-5-5') {
    this.#modelo = modelo;
    this.nombre = `Claude (${modelo})`;
  }

  async interpretar(orden: string, contactos: string[]): Promise<Intencion> {
    const { default: Anthropic } = await import('@anthropic-ai/sdk');
    const cliente = new Anthropic();
    const respuesta = await cliente.beta.messages.create({
      model: this.#modelo,
      max_tokens: 2048,
      betas: ['server-side-fallback-2026-07-01'],
      fallbacks: 'default',
      output_config: { effort: 'low', format: { type: 'json_schema', schema: ESQUEMA } },
      system: SISTEMA,
      messages: [{ role: 'user', content: `Agenda: ${JSON.stringify(contactos)}\nOrden: ${orden}` }],
    });
    if (respuesta.stop_reason === 'refusal') return { accion: 'desconocida', motivo: 'el modelo no aceptó la orden' };
    const bloque = respuesta.content.find((b) => b.type === 'text');
    if (!bloque || bloque.type !== 'text') return { accion: 'desconocida', motivo: 'el modelo no devolvió una acción' };

    const datos = JSON.parse(bloque.text) as Record<'accion' | 'contacto' | 'texto' | 'modo' | 'motivo', string>;
    if (datos.accion === 'texto' && datos.contacto && datos.texto) return { accion: 'texto', contacto: datos.contacto, texto: datos.texto };
    if (datos.accion === 'llamar' && datos.contacto) return { accion: 'llamar', contacto: datos.contacto, modo: datos.modo === 'video' ? 'video' : 'voz' };
    return { accion: 'desconocida', motivo: datos.motivo || 'orden no reconocida' };
  }
}
