// Método did:key con claves Ed25519. La clave de acuerdo X25519 se deriva de la de firma.
import { x25519PublicaDesdeEd25519 } from '../cripto/claves.ts';
import { MULTICODEC_ED25519, MULTICODEC_X25519, SERVICIO_BUZON, claveDeMultibase, multibaseDeClave, type DocumentoDid } from './documento.ts';

const PREFIJO = 'did:key:';

export function didKeyDesdeEd25519(publica: Uint8Array): string {
  return PREFIJO + multibaseDeClave(MULTICODEC_ED25519, publica);
}

/** Identificador del método de verificación principal de un did:key. */
export function kidDeDidKey(did: string): string {
  return `${did}#${did.slice(PREFIJO.length)}`;
}

export function documentoDidKey(did: string): DocumentoDid {
  if (!did.startsWith(PREFIJO)) throw new Error(`no es un did:key: ${did}`);
  return documentoDeUnaClave(did, did.slice(PREFIJO.length));
}

/**
 * Documento de una persona con una sola clave Ed25519, como el de did:key: esa clave firma (authentication,
 * assertionMethod y capabilityDelegation) y de ella se deriva la X25519 de acuerdo de claves. Los métodos se
 * identifican como «<DID>#<multibase>». También lo usa la forma compacta de did:xrpl (sección 3.3 de SPEC.md).
 */
export function documentoDeUnaClave(did: string, multibaseFirma: string, buzon?: string): DocumentoDid {
  const ed = claveDeMultibase(multibaseFirma, MULTICODEC_ED25519);
  const multibaseAcuerdo = multibaseDeClave(MULTICODEC_X25519, x25519PublicaDesdeEd25519(ed));
  const firma = `${did}#${multibaseFirma}`;
  const acuerdo = `${did}#${multibaseAcuerdo}`;
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: did,
    verificationMethod: [
      { id: firma, type: 'Multikey', controller: did, publicKeyMultibase: multibaseFirma },
      { id: acuerdo, type: 'Multikey', controller: did, publicKeyMultibase: multibaseAcuerdo },
    ],
    authentication: [firma],
    assertionMethod: [firma],
    capabilityDelegation: [firma],
    keyAgreement: [acuerdo],
    ...(buzon ? { service: [{ id: `${did}#buzon`, type: SERVICIO_BUZON, serviceEndpoint: buzon }] } : {}),
  };
}
