// Escritura atómica de archivos chicos (identidades de prueba, registros): se escribe en un archivo temporal
// y recién después se pone en su lugar, así nunca queda uno a medio escribir. Si algo falla, el temporal se borra.
import { linkSync, mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * Escribe `contenido` en `ruta`, solo legible por su dueño. Por defecto reemplaza lo que hubiera. Con
 * `soloSiNoExiste`, no toca un archivo existente y devuelve falso: por ejemplo, porque otro proceso lo creó antes.
 */
export function escribirAtomico(ruta: string, contenido: string, opciones: { soloSiNoExiste?: boolean } = {}): boolean {
  mkdirSync(dirname(ruta), { recursive: true });
  const temporal = `${ruta}.${process.pid}.tmp`;
  writeFileSync(temporal, contenido, { mode: 0o600 });
  try {
    if (!opciones.soloSiNoExiste) {
      renameSync(temporal, ruta);
      return true;
    }
    try {
      linkSync(temporal, ruta);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') return false;
      throw error;
    }
  } finally {
    // Después de un rename el temporal ya no existe; después de un link, o de un error, sí: se borra.
    rmSync(temporal, { force: true });
  }
}
