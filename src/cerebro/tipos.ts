// El "cerebro" de un agente traduce lo que la persona pide en una acción del protocolo.
// Solo interpreta órdenes de su propia persona: los mensajes que llegan nunca pasan por aquí.

export type Intencion =
  | { accion: 'texto'; contacto: string; texto: string }
  | { accion: 'llamar'; contacto: string; modo: 'voz' | 'video' }
  | { accion: 'desconocida'; motivo: string };

export interface Cerebro {
  readonly nombre: string;
  interpretar(orden: string, contactos: string[]): Promise<Intencion>;
}
