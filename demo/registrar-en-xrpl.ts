// Registra la identidad de Maxi en la red de prueba de XRP Ledger, con la forma compacta del perfil Vínculo.
//   npm run xrpl:registrar
// Solo opera en la red de prueba: sus XRP no tienen valor y la red se reinicia cada tanto. Si se reinició, volvé
// a correrlo: la cuenta sale de la semilla guardada en datos/xrpl.json, así que el DID no cambia.
// En el ledger queda público solo lo siguiente: la cuenta de prueba y la clave pública de Maxi. Ni nombre ni documento.
import { Client, RippledError, Wallet, convertStringToHex, type DIDSet } from 'xrpl';
import { cargarIdentidades, crearResolutor, guardarRegistroXrpl, leerRegistroXrpl, opcionesDeEntorno } from '../src/complemento/identidades.ts';
import { claveDeFirma } from '../src/did/documento.ts';
import { RED_DE_PRUEBA, didXrpl, formaCompacta } from '../src/did/xrpl.ts';

const paso = (texto: string) => console.log(`\n▸ ${texto}`);
const dato = (texto: string) => console.log(`  ${texto}`);
const codigoDeError = (error: unknown) => (error instanceof RippledError ? (error.data as { error?: string } | undefined)?.error : undefined);

const opciones = opcionesDeEntorno();
const { maxi } = cargarIdentidades(opciones);
const cliente = new Client(RED_DE_PRUEBA.websocket);

async function existeLaCuenta(cuenta: string): Promise<boolean> {
  try {
    await cliente.request({ command: 'account_info', account: cuenta, ledger_index: 'validated' });
    return true;
  } catch (error) {
    if (codigoDeError(error) === 'actNotFound') return false;
    throw error;
  }
}

async function objetoDid(cuenta: string): Promise<{ DIDDocument?: string; URI?: string; Data?: string } | null> {
  try {
    const { result } = await cliente.request({ command: 'ledger_entry', did: cuenta, ledger_index: 'validated' });
    return result.node as { DIDDocument?: string; URI?: string; Data?: string };
  } catch (error) {
    if (codigoDeError(error) === 'entryNotFound') return null;
    throw error;
  }
}

console.log('━━ Registro de la identidad de Maxi en la XRP Ledger (red de prueba)');
try {
  paso(`Conectando con ${RED_DE_PRUEBA.websocket}…`);
  await cliente.connect();
  const { result: servidor } = await cliente.request({ command: 'server_info' });
  const red = String(servidor.info.network_id ?? '');
  if (red !== RED_DE_PRUEBA.red) {
    throw new Error(`el servidor no es de la red de prueba (network_id ${red || 'ausente'}); no se registró nada`);
  }
  dato(`Red ${red} (red de prueba), ledger validado ${servidor.info.validated_ledger?.seq}.`);

  // 1. La cuenta que controla el objeto DID. La semilla se guarda antes de pedir fondos, para no perderla.
  let registro = leerRegistroXrpl(opciones.carpeta);
  if (!registro) {
    const nueva = Wallet.generate();
    registro = {
      version: 1,
      aviso: 'Cuenta de la red de PRUEBA de XRP Ledger para la demostración de Vínculo. No usar en la red principal.',
      red,
      semilla: nueva.seed!,
      cuenta: nueva.address,
    };
    guardarRegistroXrpl(opciones.carpeta, registro);
  }
  const cuenta = Wallet.fromSeed(registro.semilla);
  if (cuenta.address !== registro.cuenta) throw new Error('datos/xrpl.json está dañado: la semilla no corresponde a la cuenta');
  paso(`Cuenta de prueba ${cuenta.address}`);
  if (await existeLaCuenta(cuenta.address)) {
    dato('Ya existe en la red de prueba.');
  } else {
    dato('Pidiendo XRP de prueba al grifo (faucet) de la red de prueba…');
    const { balance } = await cliente.fundWallet(cuenta);
    dato(`Cuenta creada con ${balance} XRP de prueba, que no tienen valor.`);
  }

  // 2. El objeto DID, con la forma compacta: solo la clave pública de Maxi.
  const contenido = formaCompacta(maxi.billetera.clavePublica);
  const hex = convertStringToHex(contenido);
  const did = didXrpl(red, cuenta.address);
  paso(`Objeto DID: ${contenido} (${Buffer.byteLength(contenido)} de 256 bytes)`);
  const actual = await objetoDid(cuenta.address);
  if (actual?.DIDDocument?.toUpperCase() === hex && !actual.URI) {
    dato('Ya está publicado con esta clave: no hace falta otra transacción.');
  } else {
    const transaccion: DIDSet = {
      TransactionType: 'DIDSet',
      Account: cuenta.address,
      DIDDocument: hex,
      // Un campo vacío lo borra: así no queda un documento externo viejo que tape la forma compacta.
      ...(actual?.URI ? { URI: '' } : {}),
      ...(actual?.Data ? { Data: '' } : {}),
    };
    dato(actual ? 'Actualizando la clave publicada (transacción DIDSet)…' : 'Enviando la transacción DIDSet…');
    const { result } = await cliente.submitAndWait(transaccion, { wallet: cuenta, autofill: true });
    const resultado = typeof result.meta === 'object' ? result.meta.TransactionResult : 'sin resultado';
    if (resultado !== 'tesSUCCESS') throw new Error(`la transacción DIDSet terminó con ${resultado}`);
    registro.transaccion = result.hash;
    registro.registrado = new Date().toISOString();
    dato(`Validada en el ledger ${result.ledger_index}: ${resultado}.`);
  }
  registro.did = did;
  registro.registrado ??= new Date().toISOString();
  guardarRegistroXrpl(opciones.carpeta, registro);

  // 3. Comprobación independiente: el resolutor de Vínculo lee el ledger por JSON-RPC, sin esta biblioteca.
  // Puede pasar un ledger hasta que el servidor JSON-RPC vea la transacción, así que reintenta unos segundos.
  paso(`Resolviendo ${did} como lo haría el teléfono de mamá…`);
  const kid = `${did}#${(JSON.parse(contenido) as { clave: string }).clave}`;
  let clave: Uint8Array | undefined;
  for (let intento = 1; !clave; intento++) {
    try {
      clave = claveDeFirma(await crearResolutor().resolver(did), kid, 'capabilityDelegation');
    } catch (error) {
      if (intento >= 5) throw error;
      await new Promise((listo) => setTimeout(listo, 2000));
    }
  }
  if (Buffer.compare(Buffer.from(clave), Buffer.from(maxi.billetera.clavePublica)) !== 0) {
    throw new Error('la clave que publica el ledger no coincide con la de la billetera de Maxi');
  }
  dato('El ledger publica la clave de la billetera de Maxi.');

  console.log(`\n✓ Maxi tiene identidad en la XRP Ledger: ${did}`);
  console.log(`  Cuenta en el explorador: ${RED_DE_PRUEBA.explorador}/accounts/${cuenta.address}`);
  if (registro.transaccion) console.log(`  Transacción: ${RED_DE_PRUEBA.explorador}/transactions/${registro.transaccion}`);
  console.log('  Desde ahora, el complemento y la red de prueba usan esta identidad. Probala con «npm run demo:xrpl».');
} catch (error) {
  console.error(`\n✗ No se completó el registro: ${(error as Error).message}`);
  process.exitCode = 1;
} finally {
  if (cliente.isConnected()) await cliente.disconnect();
}
