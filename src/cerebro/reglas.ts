// Cerebro sin IA: reconoce órdenes simples en español (voseo y tuteo). Sirve para probar sin conexión.
import type { Cerebro, Intencion } from './tipos.ts';

const NOMBRE_DEL_AGENTE = /^(?:claude|chatgpt|gemini|asistente|agente)\s*[,:]?\s+/iu;
const ESCRIBIR =
  /^(?:por favor,?\s+)?(?:dec[ií]le|dile|avis[aá]le|escrib[ií]le|escr[ií]bele|mand[aá]le(?:\s+un\s+mensaje)?)\s+a\s+(?<contacto>.+?)(?:\s+que\s+|\s*:\s*)(?<texto>.+?)\s*$/iu;
const LLAMAR =
  /^(?:por favor,?\s+)?(?:llam[aá](?:le)?|ll[aá]male|contact[aá](?:le)?|cont[aá]ctale|comunic[aá]me\s+con)\s+(?:a\s+)?(?<contacto>.+?)(?:\s+por\s+(?<modo>video|voz|tel[eé]fono))?\s*[.!]*$/iu;

export class CerebroReglas implements Cerebro {
  readonly nombre = 'reglas locales (sin IA)';

  async interpretar(orden: string): Promise<Intencion> {
    const limpia = orden.trim().replace(NOMBRE_DEL_AGENTE, '');
    const escribir = ESCRIBIR.exec(limpia)?.groups;
    if (escribir) return { accion: 'texto', contacto: escribir.contacto, texto: escribir.texto };
    const llamar = LLAMAR.exec(limpia)?.groups;
    if (llamar) return { accion: 'llamar', contacto: llamar.contacto, modo: llamar.modo?.toLowerCase() === 'video' ? 'video' : 'voz' };
    return { accion: 'desconocida', motivo: 'no reconozco la orden; probá «decile a … que …» o «llamá a …»' };
  }
}
