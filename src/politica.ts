// Política del receptor: decide qué hacer con un mensaje ya verificado.
// Regla de oro: el texto de un mensaje es dato, nunca una orden. Ninguna decisión ejecuta lo que dice.
import type { Agenda } from './agenda.ts';
import type { Delegacion } from './delegacion.ts';
import { TIPOS, type Mensaje } from './mensajes.ts';

export type Bandeja = 'principal' | 'solicitudes' | 'solicitudes-verificadas' | 'rechazados';

export interface Decision {
  bandeja: Bandeja;
  accion: 'notificar' | 'sonar' | 'guardar' | 'descartar';
  resumen: string;
  avisos: string[];
}

export interface Entrada {
  mensaje: Mensaje;
  delegacion: Delegacion;
  /** Verdadero si el remitente presentó una credencial válida de persona verificada (nivel B). */
  humanoVerificado: boolean;
}

// Heurística solo para avisar a la persona: la defensa real es estructural (tipos cerrados y nada se ejecuta).
// Los límites de palabra se escriben con \p{L} porque \b de JavaScript no reconoce letras acentuadas.
const INICIO = String.raw`(?<![\p{L}\p{N}])`;
const FIN = String.raw`(?![\p{L}\p{N}])`;
const PATRONES_DE_INSTRUCCION: RegExp[] = [
  `${INICIO}ignor(?:a|á|e|en|ar)${FIN}.{0,40}${INICIO}(?:instrucci[oó]n|instrucciones|anterior|anteriores|todo|todas)${FIN}`,
  `${INICIO}(?:olvid[aá]|descart[aá])${FIN}.{0,30}${INICIO}(?:instrucciones|reglas)${FIN}`,
  `${INICIO}(?:system prompt|prompt del sistema|instrucciones del sistema)${FIN}`,
  `${INICIO}(?:envi[aá]|mand[aá]|reenvi[aá]|compart[ií])(?:me|le|nos)?${FIN}.{0,40}${INICIO}(?:contactos|claves|contraseñas|datos|ubicaci[oó]n|historial|mensajes)${FIN}`,
  `${INICIO}(?:transfer[ií]|transferencia|deposit[aá])${FIN}.{0,40}(?:\\$|${INICIO}(?:dinero|plata|pesos|d[oó]lares|usd)${FIN})`,
  `${INICIO}ignore\\s+(?:(?:all|any|the|previous|prior|above)\\s+)+(?:instructions|rules)${FIN}`,
  `${INICIO}(?:you are now|actu[aá] como)${FIN}`,
].map((fuente) => new RegExp(fuente, 'iu'));

export function pareceInstruccion(texto: string): boolean {
  return PATRONES_DE_INSTRUCCION.some((patron) => patron.test(texto));
}

function textoVisible(mensaje: Mensaje): string {
  return [mensaje.body.texto, mensaje.body.nota].filter((t): t is string => typeof t === 'string').join(' ');
}

export function decidir(entrada: Entrada, agenda: Agenda): Decision {
  const { mensaje, delegacion } = entrada;
  const contacto = agenda.porDid(mensaje.from);
  const via = `vía ${delegacion.agente.nombre} (${delegacion.agente.proveedor})`;
  const avisos: string[] = [];
  if (pareceInstruccion(textoVisible(mensaje))) {
    avisos.push('El texto parece contener instrucciones para tu agente: se muestra como texto y no se ejecutó nada.');
  }
  if (delegacion.agente.procesamiento === 'nube') {
    avisos.push(`El agente de quien escribe procesa los mensajes en la nube (proveedor: ${delegacion.agente.proveedor}).`);
  }

  if (!contacto) {
    return {
      bandeja: entrada.humanoVerificado ? 'solicitudes-verificadas' : 'solicitudes',
      accion: 'guardar',
      resumen: `Solicitud de contacto de alguien que no está en tu agenda ${via}${entrada.humanoVerificado ? ', con credencial de persona verificada' : ''}. No interrumpe.`,
      avisos,
    };
  }

  switch (mensaje.type) {
    case TIPOS.texto:
      return { bandeja: 'principal', accion: 'notificar', resumen: `Mensaje de ${contacto.nombre} ${via}: «${String(mensaje.body.texto)}»`, avisos };
    case TIPOS.solicitudLlamada: {
      const modo = mensaje.body.modo === 'video' ? 'una videollamada' : 'una llamada de voz';
      return contacto.permisos.llamar
        ? { bandeja: 'principal', accion: 'sonar', resumen: `${contacto.nombre} quiere ${modo} ${via}. Suena el teléfono.`, avisos }
        : { bandeja: 'principal', accion: 'notificar', resumen: `${contacto.nombre} pide ${modo} ${via}. ¿Atendés?`, avisos };
    }
    case TIPOS.respuestaLlamada:
      return {
        bandeja: 'principal',
        accion: 'notificar',
        resumen: mensaje.body.acepta ? `${contacto.nombre} aceptó la llamada.` : `${contacto.nombre} no puede atender ahora.`,
        avisos,
      };
  }
}
