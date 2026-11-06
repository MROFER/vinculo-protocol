// API pública del prototipo Vínculo.
export { Agenda, normalizarAlias, type Contacto, type IdentidadEstatal } from './agenda.ts';
export { Agente, type Notificacion, type OpcionesAgente } from './agente.ts';
export { Billetera, type OpcionesBilletera, type OpcionesDelegar } from './billetera.ts';
export { CerebroClaude } from './cerebro/claude.ts';
export { CerebroReglas } from './cerebro/reglas.ts';
export type { Cerebro, Intencion } from './cerebro/tipos.ts';
export {
  ALCANCE,
  limpiarNombreDeAgente,
  validarDatosAgente,
  verificarDelegacion,
  verificarRevocaciones,
  type DatosAgente,
  type Delegacion,
  type Procesamiento,
} from './delegacion.ts';
export { documentoDidKey, didKeyDesdeEd25519 } from './did/clave.ts';
export type { DocumentoDid } from './did/documento.ts';
export { MetodoKey, MetodoWeb, Resolutor, type MetodoDid } from './did/resolutor.ts';
export { MetodoXrpl, RED_DE_PRUEBA, didXrpl, formaCompacta, type FormaCompacta } from './did/xrpl.ts';
export { firmanteDeClave, firmarVinculacion, verificarVinculacion, type FirmanteDocumento, type OpcionesVinculacion } from './identidad/nivel-a.ts';
export { comprobarRevocacion, leerCrl, usosDeClave, type ListaRevocacion, type UsoDeClave } from './identidad/x509.ts';
export { EmisorSimulado, presentar, verificarPresentacion } from './identidad/nivel-b.ts';
export { TIPOS, VIGENCIA_MAXIMA, validarMensaje, type Mensaje, type TipoMensaje } from './mensajes.ts';
export { decidir, pareceInstruccion, type Bandeja, type Decision } from './politica.ts';
export { ClienteBuzon, depositar, obtenerRevocaciones, publicarRevocaciones } from './relay/cliente.ts';
export { ServidorBuzon } from './relay/servidor.ts';
export { cifrar, descifrar, leerCabeceraSobre } from './sobre.ts';
export { crearTarjeta, leerTarjeta, type Tarjeta } from './tarjeta.ts';
export { VistosEnArchivo, VistosEnMemoria, claveDeMensaje, type RegistroVistos } from './vistos.ts';
