# Protocolo Vínculo — especificación v0.1 (borrador)

**Estado:** borrador de trabajo, 6 de noviembre de 2026. La implementación de referencia está en este repositorio (`src/`) y cada regla de esta especificación tiene una prueba en `test/`.

**Nombre:** «Vínculo» es un nombre de trabajo.

Las palabras **DEBE**, **NO DEBE**, **DEBERÍA** y **PUEDE** se usan con el sentido de RFC 2119.

## 1. Objetivo

Vínculo permite que el agente de IA de una persona se comunique con el de otra, por un canal cifrado de extremo a extremo, sin importar qué empresa provee cada agente. Hay tres principios:

1. **La identidad es de la persona.** Se expresa con un DID (W3C) cuyas claves guarda la persona en su dispositivo. Ningún proveedor de IA es dueño de la identidad ni de la agenda.
2. **El agente es un delegado.** Tiene su propia clave y actúa con una delegación firmada por la persona, con alcance limitado, vencimiento y revocación.
3. **El contenido es dato, nunca orden.** Lo que llega se muestra a la persona. Ningún texto recibido se ejecuta como instrucción.

## 2. Terminología

| Término | Definición |
| --- | --- |
| Persona | Titular de una identidad Vínculo (un DID). |
| Billetera | Componente del dispositivo de la persona que guarda sus claves, emite delegaciones, revoca y descifra. |
| Agente | Software, normalmente un modelo de IA, que actúa por la persona. Tiene su propio DID (`did:key`). |
| Delegación | JWT firmado por la persona que autoriza a un agente. |
| Buzón | Servidor de almacenamiento y reenvío elegido por la persona. Guarda sobres cifrados que no puede leer. |
| Sobre | JWE que transporta un mensaje firmado. |
| Contacto | Persona registrada en la agenda de otra, por su DID. |

## 3. Identidad

### 3.1 Métodos DID

- Toda implementación **DEBE** soportar `did:key` con claves Ed25519.
- **PUEDE** soportar `did:web` y `did:xrpl` (sección 3.3).
- La resolución **DEBE** comprobar que el `id` del documento resuelto coincide con el DID pedido.

### 3.2 Claves

- La firma usa Ed25519 (EdDSA, RFC 8037). La clave de firma de la persona **DEBE** figurar en `assertionMethod` y `capabilityDelegation`, y la del agente en `assertionMethod` y `authentication`.
- El acuerdo de claves usa X25519. En `did:key` y en la forma compacta de `did:xrpl` (sección 3.3), la clave X25519 se deriva de la Ed25519 con el mapa birracional `u = (1 + y) / (1 − y) mod p`, y la privada como `SHA-512(semilla)[0..32]`.
- Una persona **PUEDE** publicar su buzón como servicio de tipo `VinculoBuzon`.

### 3.3 Perfil `did:xrpl`

El DID tiene la forma `did:xrpl:<red>:<cuenta>`. `<cuenta>` es la dirección clásica de la cuenta que controla el objeto DID (XLS-40) y `<red>` es el NetworkID de XRP Ledger, por ejemplo `1` para la red de prueba. XLS-40 no fija qué número corresponde a cada red, así que la correspondencia entre número de red y servidor se configura explícitamente. El resolutor **DEBE** leer el objeto DID de un ledger validado.

Los campos `URI`, `Data` y `DIDDocument` del objeto DID admiten como máximo 256 bytes cada uno, y un documento DID completo no entra. Por eso el perfil admite dos formas:

- **Forma compacta.** `DIDDocument` contiene, en UTF-8, el JSON `{"vinculo":1,"clave":"<multibase Ed25519>"}`, con un campo opcional `buzon` (URL HTTPS). El resolutor arma el documento completo igual que en `did:key`: la clave figura en `authentication`, `assertionMethod` y `capabilityDelegation`, la X25519 derivada de ella en `keyAgreement` y el buzón, si está, como servicio `VinculoBuzon`. Cada método se identifica como `<DID>#<multibase>`. El resolutor **DEBE** rechazar un valor de `vinculo` que no conozca.
- **Documento externo.** `URI` **DEBE** apuntar por HTTPS al documento DID completo y `Data` **DEBE** contener `sha256:<hex>` de ese documento. El resolutor **DEBE** rechazar un documento cuyo hash no coincida. Si el objeto tiene `URI`, se usa esta forma.

Para cambiar de clave, la persona envía otra transacción `DIDSet`: el DID no cambia y lo firmado con la clave anterior deja de verificarse. Un resolutor **PUEDE** guardar un documento resuelto por poco tiempo (el prototipo lo guarda 60 segundos); es lo máximo que tarda en notarse un cambio de clave.

## 4. Delegación

### 4.1 Formato

Es un JWS compacto con cabecera `{"alg":"EdDSA","typ":"vinculo-delegacion+jwt","kid":"<DID de la persona>#<clave>"}` y estos claims:

| Claim | Contenido |
| --- | --- |
| `iss` | DID de la persona. |
| `sub` | DID del agente. |
| `jti` | Identificador único, usado para revocar. |
| `iat`, `nbf`, `exp` | Vigencia. **DEBERÍA** durar 30 días o menos. |
| `alcance` | Lista de permisos: tipos de mensaje (sección 5.2), `buzon:leer` y `billetera:descifrar`. |
| `agente` | `{nombre, proveedor, procesamiento}`, donde `procesamiento` vale `local`, `enclave` o `nube`. `nombre` y `proveedor` tienen de 1 a 40 caracteres: letras, números, espacios y `. _ & ' + -`, empezando por letra o número. Así no pueden traer saltos de línea ni signos que imiten el formato de un mensaje. |

### 4.2 Verificación

Quien verifica **DEBE** resolver `iss`, verificar la firma con una clave de `capabilityDelegation` y comprobar la vigencia (con 60 s de tolerancia). También **DEBE** comprobar que `sub` es el agente que firmó, que `alcance` incluye la operación, que `agente` cumple la sección 4.1 y que el `jti` no está revocado.

### 4.3 Revocación

- La persona publica una lista firmada `{"typ":"vinculo-revocaciones+jwt"}` con los claims `iss`, `iat`, `version` (entero creciente) y `revocadas` (lista de `jti`).
- La lista se publica en el buzón propio (`PUT /v1/estado/{did}`). El buzón **DEBE** verificar la firma y **DEBE** rechazar una versión menor o igual a la guardada (código 409).
- Quien recibe un mensaje **DEBE** consultar la lista en el buzón del remitente antes de aceptar la delegación. Ese buzón es el de su agenda o, si el remitente no es un contacto, el que publica su documento DID (servicio `VinculoBuzon`). **NO DEBE** usarse el `reply_to` del mensaje, porque lo elige quien escribe: un agente revocado podría indicar un buzón sin revocaciones, y el teléfono de quien recibe le avisaría al remitente cuándo leyó.
- Si no hay buzón conocido (por ejemplo, un `did:key` que no está en la agenda), la revocación no se puede comprobar. El mensaje solo **PUEDE** ir a una bandeja de solicitudes, con un aviso.

## 5. Mensajes

### 5.1 Mensaje en claro

Los campos de nivel superior siguen DIDComm v2:

| Campo | Obligatorio | Contenido |
| --- | --- | --- |
| `id` | sí | Identificador único (hasta 100 caracteres). |
| `type` | sí | Tipo de mensaje (5.2). |
| `from` | sí | DID de la **persona** que envía. |
| `to` | sí | DIDs de las personas destinatarias. |
| `created_time`, `expires_time` | sí | Segundos Unix. `expires_time` **DEBE** ser posterior a `created_time` y como máximo 7 días después. |
| `body` | sí | Contenido según el tipo. |
| `delegation` | sí | JWT de delegación del agente que envía. |
| `reply_to` | no | URL del buzón donde responder. No sirve para buscar revocaciones (4.3). |
| `presentation` | no | Credencial SD-JWT presentada (sección 9.2). |

Un mensaje con campos desconocidos **DEBE** rechazarse.

### 5.2 Tipos de la versión 0.1

El conjunto es cerrado: un tipo desconocido **DEBE** rechazarse. Los campos de `body` también son cerrados.

| `type` | `body` |
| --- | --- |
| `vinculo/texto/1.0` | `texto` (1 a 4000 caracteres). |
| `vinculo/llamada/1.0/solicitud` | `modo` (`voz` o `video`); opcionales: `urgencia` (`normal` o `alta`) y `nota`. |
| `vinculo/llamada/1.0/respuesta` | `acepta` (booleano) y `en_respuesta_a` (id); opcional: `nota`. |

## 6. Firma y cifrado

1. **Firma.** El agente firma el mensaje en claro como JWS compacto: `{"alg":"EdDSA","typ":"vinculo-mensaje+jws","kid":"<DID del agente>#<clave>"}`.
2. **Sobre.** El JWS se cifra como JWE compacto (RFC 7516) para la primera clave `keyAgreement` del destinatario:
   - cabecera protegida `{"alg":"ECDH-ES","enc":"A256GCM","typ":"vinculo-sobre+jwe","cty":"vinculo-mensaje+jws","kid":"<clave del destinatario>","epk":{"kty":"OKP","crv":"X25519","x":"…"}}`;
   - clave de contenido: Concat KDF con SHA-256 (RFC 7518, sección 4.6.2), `AlgorithmID = "A256GCM"`, `apu` y `apv` vacíos, 256 bits;
   - la clave cifrada queda vacía (acuerdo directo); IV de 96 bits; etiqueta de 128 bits; AAD = cabecera en base64url.

El remitente viaja dentro del cifrado: el buzón solo conoce al destinatario.

## 7. Procesamiento en el receptor

El agente receptor **DEBE** aplicar estos pasos en orden y descartar el mensaje ante el primer fallo:

1. Pedir a la billetera que descifre. La billetera **DEBE** exigir una delegación propia, vigente, no revocada y con `billetera:descifrar`.
2. Verificar la firma del JWS con la clave `assertionMethod` del DID del agente indicado en `kid`.
3. Validar la forma del mensaje (5.1 y 5.2).
4. Comprobar que `to` incluye a la persona receptora.
5. Comprobar que no venció y que su fecha no es futura (tolerancia: 300 s).
6. Rechazar `id` ya procesados del mismo remitente. El registro de lo procesado es de la persona, no del agente: **DEBE** sobrevivir a la renovación del agente y a los reinicios, y guardar cada `id` hasta que su mensaje venza. Un mensaje que no se pudo borrar del buzón **NO DEBE** volver a mostrarse.
7. Verificar la delegación (4.2) con `iss = from`, `sub = agente firmante`, alcance igual a `type` y revocaciones al día.
8. Si hay `presentation`, verificarla con `aud` igual a la persona receptora y `nonce` igual al `id` del mensaje.
9. Aplicar la política (sección 8).

## 8. Política del receptor

- El contenido **NO DEBE** interpretarse como instrucción para el agente. Cualquier acción con efectos fuera de mostrar o hacer sonar **DEBE** pedir aprobación humana.
- Un remitente fuera de la agenda **DEBE** ir a una bandeja de solicitudes que no interrumpe. Si presentó una credencial válida de persona verificada, **PUEDE** ir a una bandeja de solicitudes verificadas.
- Una solicitud de llamada de un contacto con permiso de llamada **PUEDE** hacer sonar el dispositivo.
- La interfaz **DEBERÍA** avisar cuando el agente remitente procesa en la nube (`procesamiento = nube`) y cuando el texto parece contener instrucciones.
- Todo lo que viene del remitente y se le muestra a un asistente de IA (textos, notas y los motivos de un rechazo, que pueden citar datos del mensaje) **DEBE** ir entre comillas o escapado, para que no pueda imitar el formato de la respuesta.

## 9. Identidad estatal (opcional)

### 9.1 Nivel A: autovinculación

- Es un JWS `{"alg":"RS256","typ":"vinculo-vinculacion+jws","x5c":[…]}` firmado con el certificado de firma avanzada del documento de identidad, con los claims `did`, `iat` y `declaracion`.
- Quien verifica **DEBE** validar la cadena `x5c` hasta una raíz de confianza configurada (en Uruguay, la raíz nacional), la vigencia de cada certificado y que el certificado final no sea de una autoridad.
- El certificado final **DEBE** tener el uso de clave «no repudio» (`nonRepudiation`): el de firma, no el de autenticación que trae el mismo documento. Las autoridades de la cadena, si declaran usos de clave, **DEBEN** incluir el de firmar certificados.
- Quien verifica **DEBE** comprobar que ningún certificado de la cadena fue revocado, con una lista de revocación (CRL, RFC 5280) de cada autoridad: firmada por ella, vigente (con `nextUpdate`) y sin extensiones críticas que no conozca. Si falta la lista de alguna autoridad o venció, la vinculación **DEBE** rechazarse. Las listas se obtienen de los puntos de distribución de los certificados y se renuevan antes de vencer. OCSP queda para una versión posterior.
- La vinculación revela nombre y número de documento. **NO DEBE** publicarse en un ledger.

### 9.2 Nivel B: credencial SD-JWT

- Es una credencial SD-JWT (RFC 9901) con `typ` `dc+sd-jwt`, `cnf.jwk` igual a la clave de la persona y `_sd_alg` igual a `sha-256`. La emite un emisor de una lista de confianza.
- La presentación **DEBE** incluir un KB-JWT (`typ` `kb+jwt`) con `aud`, `nonce`, `iat` (300 s de ventana) y `sd_hash`.

### 9.3 Nivel C

Las pruebas de conocimiento cero sobre el chip del documento quedan fuera de la versión 0.1.

## 10. Buzón (API HTTP)

| Método y ruta | Autorización | Respuesta |
| --- | --- | --- |
| `POST /v1/buzon/{did}` | ninguna | 202 `{id}`. El cuerpo es el JWE (hasta 64 KiB). Responde 429 si hay 500 sobres pendientes. |
| `GET /v1/buzon/{did}` | persona o agente con `buzon:leer` | 200 `{sobres:[{id, recibido, jwe}]}` |
| `DELETE /v1/buzon/{did}/{id}` | persona o agente con `buzon:leer` | 204 |
| `PUT /v1/estado/{did}` | firma de la lista | 204 o 409 |
| `GET /v1/estado/{did}` | ninguna | 200 `{revocaciones}` o 404 |

**Autorización.** Se envía `Authorization: Vinculo <JWS>` con `typ` `vinculo-acceso+jws`, firmado con una clave `authentication`. Los claims son `iss`, `htm` (método), `htu` (ruta), `iat` (±120 s), `jti` (de un solo uso) y, si firma un agente, `delegation`.

## 11. Contactos

Una tarjeta es un JWS `{"typ":"vinculo-tarjeta+jws"}` firmado por la persona, con los claims `did`, `nombre`, `buzon`, `iat` y, opcionalmente, `vinculacion` (9.1). Las tarjetas **DEBERÍAN** intercambiarse en persona. Con vinculación, la tarjeta ocupa unos 4 KB y no entra en un QR, así que se envía por el canal cifrado después del emparejamiento.

## 12. Seguridad y privacidad

| Riesgo | Tratamiento en v0.1 |
| --- | --- |
| Inyección de instrucciones | Tipos y campos cerrados, contenido mostrado como dato y aprobación humana (sección 8). |
| Spam | Bandeja de solicitudes; credenciales de persona verificada; límites del buzón. |
| Agente robado | Delegación con alcance, vencimiento y revocación; el buzón y la billetera la exigen. |
| Repetición | `id` único, vigencia y `jti` de un solo uso en el buzón. |
| Buzón malicioso | Puede retener sobres o listas de revocación, pero no leerlos ni falsificarlos. Para acotar el daño de una retención, las delegaciones duran poco. |
| Metadatos | El buzón ve destinatario, tamaño y hora. |
| Secreto hacia adelante | No lo hay en v0.1: una clave robada descifra mensajes pasados que se hayan guardado. La versión 0.2 debe adoptar MLS (RFC 9420). |
| Rotación de claves | `did:key` no permite rotar; `did:web` y `did:xrpl` sí. |
| Proveedor de IA | Si el agente procesa en la nube, el proveedor ve el contenido. El campo `procesamiento` lo hace explícito. |
| Datos personales | Ningún dato personal se guarda en ledgers (Ley 18.331). La vinculación A y las credenciales B se comparten solo con quien la persona elige. |

## 13. Diferencias con DIDComm v2.1

Para converger con DIDComm en una versión futura:

- DIDComm usa `ECDH-ES+A256KW` con serialización JSON (varios destinatarios); Vínculo 0.1 usa `ECDH-ES` directo y compacto (un destinatario).
- DIDComm recomienda authcrypt (ECDH-1PU); Vínculo firma y luego cifra de forma anónima, porque necesita la firma del agente para encadenar la delegación.
- DIDComm identifica los tipos de mensaje con URIs resolubles; Vínculo 0.1 usa cadenas cortas.

## 14. Trabajo futuro

1. MLS para grupos y secreto hacia adelante.
2. Nivel C, con pruebas de conocimiento cero sobre el chip del documento.
3. Firma del nivel A con el documento real (PKCS#11), usando la raíz nacional como ancla.
4. Emisión del nivel B sobre ID Uruguay (OpenID Connect hoy; OpenID4VCI después).
5. Señalización de voz y video (WebRTC) dentro del canal.
6. Convergencia con DIDComm v2.1 y con el W3C AI Agent Protocol Community Group.
