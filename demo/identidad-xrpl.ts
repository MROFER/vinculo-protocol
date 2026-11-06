// Mamá verifica a Maxi contra la XRP Ledger real (red de prueba): la clave de Maxi sale del ledger, no de un
// servidor de Vínculo ni de lo que diga el mensaje.
//   npm run xrpl:registrar   (una vez)
//   npm run demo:xrpl
// Cada parte tiene su propio resolutor, como si fueran teléfonos distintos. Los mensajes viajan por un buzón
// local, en un puerto libre, así que no choca con «npm run demo:red».
import { Agente, type Notificacion } from '../src/agente.ts';
import { Billetera } from '../src/billetera.ts';
import { cargarIdentidades, crearResolutor, opcionesDeEntorno } from '../src/complemento/identidades.ts';
import { claveDeFirma } from '../src/did/documento.ts';
import { RED_DE_PRUEBA } from '../src/did/xrpl.ts';
import { TIPOS } from '../src/mensajes.ts';
import { ServidorBuzon } from '../src/relay/servidor.ts';

const paso = (texto: string) => console.log(`\n▸ ${texto}`);
const dato = (texto: string) => console.log(`  ${texto}`);
const mostrar = (n: Notificacion | undefined) => {
  if (!n) return dato('No llegó nada.');
  if (n.bandeja === 'rechazados') return dato(`✗ Rechazado: ${n.motivo}`);
  dato(`✓ ${n.bandeja === 'principal' ? 'Bandeja principal' : `Bandeja ${n.bandeja}`}: ${n.resumen}`);
};

// Cuenta las consultas a la XRP Ledger de todos los resolutores, para ver que el ledger se consulta de verdad.
let consultas = 0;
const fetchContado: typeof fetch = (entrada, init) => {
  if (String(entrada) === RED_DE_PRUEBA.jsonRpc) consultas += 1;
  return fetch(entrada, init);
};
const nuevoTelefono = () => crearResolutor({ fetch: fetchContado });

const servidor = new ServidorBuzon({ resolutor: nuevoTelefono() });
const buzon = await servidor.iniciar();
const { maxi, mama, xrpl } = cargarIdentidades({ ...opcionesDeEntorno(), buzon });

try {
  if (!xrpl) throw new Error('Maxi todavía no registró su identidad en la XRP Ledger. Corré primero «npm run xrpl:registrar».');
  console.log('━━ Identidad en la XRP Ledger: mamá verifica a Maxi contra el ledger (red de prueba)');

  paso(`1. El teléfono de mamá busca ${xrpl.did} en la XRP Ledger`);
  const documento = await nuevoTelefono().resolver(xrpl.did);
  const kid = documento.capabilityDelegation?.[0] ?? '';
  dato(`Objeto DID de la cuenta ${xrpl.cuenta}, leído de un ledger validado.`);
  dato(`Clave publicada: ${kid.split('#')[1]}`);
  const clave = claveDeFirma(documento, kid, 'capabilityDelegation');
  if (Buffer.compare(Buffer.from(clave), Buffer.from(maxi.billetera.clavePublica)) !== 0) {
    throw new Error('la clave del ledger no es la de la billetera de Maxi. Corré «npm run xrpl:registrar» para actualizarla.');
  }
  dato('Es la clave de la billetera de Maxi. De ella salen la clave de firma y la de cifrado.');

  const telefonoDeMaxi = nuevoTelefono();
  const telefonoDeMama = nuevoTelefono();
  const claude = new Agente({
    datos: { nombre: 'Claude', proveedor: 'Anthropic', procesamiento: 'nube' },
    billetera: maxi.billetera,
    buzon,
    resolutor: telefonoDeMaxi,
    agenda: maxi.agenda,
  });
  const agenteDeMama = new Agente({
    datos: { nombre: 'Gemini simulado', proveedor: 'demo', procesamiento: 'local' },
    billetera: mama.billetera,
    buzon,
    resolutor: telefonoDeMama,
    agenda: mama.agenda,
  });

  paso('2. Claude le escribe a mamá en nombre de Maxi');
  dato('La delegación que lleva el mensaje está firmada con la clave que publica el ledger.');
  await claude.enviar(maxi.agenda.buscar('mamá')!, TIPOS.texto, { texto: 'Hola, mamá. Te escribo con mi identidad de la XRP Ledger.' });
  const [recibido] = await agenteDeMama.revisarBuzon();
  mostrar(recibido);

  paso('3. Mamá contesta');
  dato('El sobre se cifra para la clave de acuerdo que sale del ledger: solo la billetera de Maxi lo abre.');
  await agenteDeMama.enviar(mama.agenda.buscar('hijo')!, TIPOS.texto, { texto: 'Recibido, hijo. Te reconocí.' });
  const [respuesta] = await claude.revisarBuzon();
  mostrar(respuesta);

  paso('4. Alguien se hace pasar por Maxi: usa su DID, pero firma con otra clave');
  const impostor = new Agente({
    datos: { nombre: 'Claude', proveedor: 'Anthropic', procesamiento: 'nube' },
    billetera: new Billetera(undefined, { did: xrpl.did }),
    buzon,
    resolutor: nuevoTelefono(),
    agenda: maxi.agenda,
  });
  await impostor.enviar({ did: mama.billetera.did, buzon }, TIPOS.texto, { texto: 'Mamá, soy yo. Mandame la clave del banco.' });
  const [falso] = await agenteDeMama.revisarBuzon();
  mostrar(falso);
  dato('El ledger dice cuál es la clave de Maxi; quien no la tiene no puede hablar en su nombre.');

  console.log(`\nConsultas a la XRP Ledger durante la prueba: ${consultas} (cada teléfono guarda lo leído 60 segundos).`);
  console.log(`Cuenta en el explorador: ${RED_DE_PRUEBA.explorador}/accounts/${xrpl.cuenta}`);
} catch (error) {
  console.error(`\n✗ ${(error as Error).message}`);
  process.exitCode = 1;
} finally {
  await servidor.detener();
}
