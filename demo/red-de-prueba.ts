// Red de prueba para el complemento: un buzón y el teléfono de mamá, con un agente SIMULADO.
//   npm run demo:red
// Dejala abierta en una terminal mientras usás el complemento desde Claude:
//   - lo que llega a mamá se muestra acá, con lo que decidió su política;
//   - las llamadas se atienden solas a los 2 segundos;
//   - lo que escribas acá y mandes con Enter se lo envía mamá a Maxi.
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { Agente, type Notificacion } from '../src/agente.ts';
import { cargarIdentidades, crearResolutor, opcionesDeEntorno } from '../src/complemento/identidades.ts';
import { TIPOS } from '../src/mensajes.ts';
import { ServidorBuzon } from '../src/relay/servidor.ts';
import { VistosEnArchivo } from '../src/vistos.ts';

const corto = (did: string) => `${did.slice(0, 16)}…${did.slice(-6)}`;
const hora = () => new Date().toLocaleTimeString('es-UY', { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
const decir = (texto: string) => console.log(`[${hora()}] ${texto}`);

const { maxi, mama, buzon, xrpl, carpeta } = cargarIdentidades(opcionesDeEntorno());
// Con identidad en la XRP Ledger, el teléfono de mamá busca la clave de Maxi en la red de prueba.
const resolutor = crearResolutor();
const direccion = new URL(buzon);
const servidor = new ServidorBuzon({ resolutor });
try {
  await servidor.iniciar(Number(direccion.port), direccion.hostname);
} catch (error) {
  console.error(`No pude abrir el buzón en ${buzon}: ${(error as Error).message}. ¿Ya hay otra red de prueba abierta?`);
  process.exit(1);
}

const agente = new Agente({
  datos: { nombre: 'Gemini simulado', proveedor: 'demo', procesamiento: 'local' },
  billetera: mama.billetera,
  buzon,
  resolutor,
  agenda: mama.agenda,
  duracion: 24 * 3600,
  vistos: new VistosEnArchivo(join(carpeta, 'vistos-mama.json')),
});
const hijo = mama.agenda.porDid(maxi.billetera.did)!;

console.log('━━ Red de prueba de Vínculo');
console.log(`   Buzón: ${buzon} (en la realidad, cada persona elige el suyo)`);
console.log(`   Maxi: ${xrpl ? `${maxi.billetera.did}, registrado en la XRP Ledger (red de prueba)` : corto(maxi.billetera.did)}`);
console.log(`   Mamá: ${corto(mama.billetera.did)}, con un agente simulado en este teléfono`);
console.log('   Pedile a Claude «decile a mamá que…» o «llamá a mamá». Lo que escribas acá se lo manda mamá a Maxi.');
console.log('   Ctrl+C para cerrar.\n');

async function atender(llamada: Notificacion): Promise<void> {
  await new Promise((listo) => setTimeout(listo, 2000));
  await agente.enviar(hijo, TIPOS.respuestaLlamada, { acepta: true, en_respuesta_a: llamada.mensaje!.id });
  decir('Mamá atendió. (La voz iría directa entre los teléfonos; el prototipo solo acuerda la llamada.)');
}

async function revisar(): Promise<void> {
  try {
    for (const n of await agente.revisarBuzon()) {
      const marca = n.bandeja === 'rechazados' ? '✗' : n.accion === 'sonar' ? '☎' : '•';
      decir(`${marca} [${n.bandeja}] ${n.resumen}${n.motivo ? `: ${n.motivo}` : ''}`);
      for (const aviso of n.avisos) console.log(`           ⚠ ${aviso}`);
      if (n.accion === 'sonar' && n.mensaje?.from === hijo.did) await atender(n);
    }
  } catch (error) {
    decir(`No pude revisar el buzón: ${(error as Error).message}`);
  }
  setTimeout(revisar, 1000);
}
void revisar();

const entrada = createInterface({ input: process.stdin });
entrada.on('line', (linea) => {
  const texto = linea.trim();
  if (!texto) return;
  agente
    .enviar(hijo, TIPOS.texto, { texto })
    .then(() => decir(`→ Mamá le escribió a Maxi: «${texto}»`))
    .catch((error: Error) => decir(`No se pudo enviar: ${error.message}`));
});

process.on('SIGINT', () => {
  entrada.close();
  void servidor.detener().then(() => process.exit(0));
});
