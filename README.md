# Vínculo — prototipo

Prototipo de un protocolo abierto para que el agente de IA de una persona (Claude, ChatGPT, Gemini u otro) se comunique con el agente de otra persona por un canal cifrado. La identidad pertenece a la persona, no al proveedor de IA, y puede vincularse con la identidad digital del Estado uruguayo.

> **In English:** Vínculo is an open protocol that lets one person's AI agent (Claude, ChatGPT, Gemini or any other) talk to another person's agent over an end-to-end encrypted channel, whichever company provides each agent. Identity belongs to the person, not to the AI provider: it is a W3C DID that can be anchored on the XRP Ledger and linked to Uruguay's national digital ID. Agents act under signed, scoped and revocable delegations, and received messages are treated as data, never as instructions. This repository holds the draft specification (in Spanish) and a TypeScript reference implementation, including an MCP plugin for AI assistants. Licensed under Apache-2.0.

- Especificación: [SPEC.md](SPEC.md)
- Propuesta para el Estado uruguayo (contexto, estrategia y piloto): documento aparte, todavía no publicado.

## Cómo probarlo

Requiere Node.js 22.18 o superior (corre TypeScript directo, sin compilar). El núcleo no tiene dependencias. El complemento para asistentes usa el SDK oficial de MCP y el registro en la XRP Ledger usa la biblioteca oficial `xrpl`. Se instalan una vez:

```bash
npm install
```

```bash
npm test
```

```bash
npm run demo
```

Para que Claude interprete las órdenes en lugar de las reglas locales, hacen falta credenciales de Anthropic (`ANTHROPIC_API_KEY` o `ant auth login`):

```bash
npm run demo:claude
```

Para revisar los tipos:

```bash
npm run tipos
```

## Qué muestra la demo

1. Dos personas crean su identidad (`did:key`) en sus teléfonos.
2. **Nivel A:** Maxi vincula su identidad con su documento firmando con el certificado de firma avanzada. El teléfono de mamá comprueba la cadena hasta la raíz y, con las listas de revocación, que ningún certificado fue revocado. La autoridad certificadora es simulada.
3. Intercambian tarjetas de contacto en persona y el teléfono de mamá verifica la cadena de certificados.
4. Cada uno delega en el agente que prefiere (Claude y Gemini), con alcance y vencimiento.
5. «Claude, decile a mi madre que llego a las 8»: el mensaje llega cifrado, firmado y verificado. El buzón no ve remitente ni contenido.
6. «Claude, llamá a mi madre»: el teléfono de mamá suena y la respuesta vuelve.
7. Un desconocido intenta colar instrucciones: va a solicitudes y nada se ejecuta.
8. **Nivel B:** una vecina se presenta con una credencial del Estado (simulada) y revela solo que es una persona verificada.
9. Maxi revoca a Claude y delega en otro agente: el agente viejo queda afuera y mamá no tiene que cambiar nada.

## Complemento para Claude

El complemento le da a Claude, o a cualquier asistente compatible con MCP, una «línea» Vínculo: puede escribir, revisar mensajes y pedir llamadas en nombre de Maxi, con delegación firmada y sin tocar sus claves.

1. Abrí la red de prueba en una terminal y dejala abierta. Simula el buzón y el teléfono de mamá: muestra lo que le llega, atiende las llamadas sola a los 2 segundos, y lo que escribas ahí se lo manda mamá a Maxi.

    ```bash
    npm run demo:red
    ```

2. Conectá Claude de una de estas dos formas:
    - **Claude Code**, incluida la pestaña Code de la app de escritorio: abrí una sesión en esta carpeta. El archivo `.mcp.json` declara el complemento `vinculo`, y Claude Code pide permiso para activarlo la primera vez.
    - **App de Claude para computadora (chat):** en la configuración de desarrollador de la app (*Settings → Developer → Edit Config*) se abre `claude_desktop_config.json`. Agregá esto, con la ruta completa a tu carpeta del proyecto, y reiniciá la app:

    ```json
    {
      "mcpServers": {
        "vinculo": {
          "command": "node",
          "args": ["--disable-warning=ExperimentalWarning", "C:/ruta/al/proyecto/src/complemento/servidor-mcp.ts"]
        }
      }
    }
    ```

3. Pedile cosas como «decile a mamá que llego a las 8», «llamá a mamá» o «¿tengo mensajes nuevos en Vínculo?».

| Herramienta | Qué hace |
| --- | --- |
| `contactos` | Lista la agenda de Vínculo de Maxi. |
| `enviar_mensaje` | Manda un texto firmado por el asistente, con la delegación de Maxi, y cifrado para el contacto. |
| `revisar_mensajes` | Trae lo que llegó, marcado como contenido de terceros y con los avisos de la política. |
| `llamar` | Pide una llamada y espera la respuesta hasta 20 segundos. Solo acuerda la llamada: todavía no hay voz. |
| `estado` | Muestra quién es la persona, qué asistente actúa en su nombre y qué permite la delegación. |

Por dentro, el asistente se presenta al conectarse (por ejemplo, «Claude») y la billetera de Maxi le delega permisos por 12 horas a una clave nueva del agente. Lo que llega pasa por la política de Maxi antes de que el asistente lo lea, y se le entrega como dato, nunca como orden.

Las identidades de prueba se crean solas la primera vez en `datos/`, que git ignora, junto con el registro de mensajes ya vistos de cada persona (`vistos-maxi.json` y `vistos-mama.json`). Para empezar de cero, borrá esa carpeta. Variables opcionales: `VINCULO_DATOS` (otra carpeta) y `VINCULO_BUZON` (otro buzón; por defecto, `http://127.0.0.1:8787`).

## Identidad en la XRP Ledger

Maxi puede registrar su identidad en la red de prueba de XRP Ledger (Testnet), donde los XRP no tienen valor. Queda un DID de la forma `did:xrpl:1:r…` que cualquiera puede leer del ledger, sin pasar por un servidor de Vínculo.

```bash
npm run xrpl:registrar
```

El script crea una cuenta de prueba, le pide XRP de prueba al grifo (*faucet*) de la red y publica con una transacción `DIDSet` la forma compacta del perfil Vínculo, `{"vinculo":1,"clave":"z6Mk…"}`: 72 de los 256 bytes que admite el campo. En el ledger quedan solo la cuenta y la clave pública de Maxi, sin nombre ni documento. Al final muestra los enlaces al explorador de la red de prueba. Se puede volver a correr: si la clave ya está publicada, no envía nada; si la red de prueba se reinició, vuelve a crear la cuenta con la misma dirección, así que el DID no cambia.

```bash
npm run demo:xrpl
```

La demostración hace que el teléfono de mamá busque el DID de Maxi en el ledger, reciba un mensaje que Claude le manda en nombre de Maxi y le conteste. También rechaza a un impostor que usa el DID de Maxi pero firma con otra clave.

Una vez registrado, el complemento y `npm run demo:red` usan el `did:xrpl` de Maxi, y la verificación consulta la red de prueba. La semilla de la cuenta de prueba queda en `datos/xrpl.json`; si borrás ese archivo, Maxi vuelve a usar `did:key`.

## Estructura

| Ruta | Qué hace |
| --- | --- |
| `src/cripto/claves.ts` | Ed25519, X25519 y la conversión entre ambas. |
| `src/did/` | Documentos DID y resolución de `did:key`, `did:web` y `did:xrpl` (perfil Vínculo, con la forma compacta en `xrpl.ts`). |
| `src/jose.ts`, `src/sobre.ts` | JWS (EdDSA y RS256) y JWE (ECDH-ES, X25519, A256GCM). |
| `src/billetera.ts` | Claves de la persona, delegaciones, revocaciones y descifrado. |
| `src/delegacion.ts` | Formato y verificación de delegaciones y revocaciones. |
| `src/agente.ts` | Envío y recepción con los pasos normativos de la especificación. |
| `src/politica.ts` | Bandejas y detección de instrucciones escondidas. |
| `src/vistos.ts` | Registro de mensajes ya procesados, en memoria o en archivo, para rechazar repeticiones. |
| `src/archivos.ts` | Escritura atómica de los archivos locales. |
| `src/relay/` | Buzón HTTP (servidor y cliente) con autorización firmada. |
| `src/identidad/nivel-a.ts` | Vinculación con el documento (JWS con cadena X.509). |
| `src/identidad/x509.ts` | Usos de clave de un certificado y listas de revocación (CRL), con un lector DER mínimo. |
| `src/identidad/nivel-b.ts` | Credenciales SD-JWT (RFC 9901) con prueba de posesión. |
| `src/cerebro/` | Interpretación de órdenes: reglas locales o Claude (`claude-opus-5-5`). |
| `src/complemento/` | Complemento MCP para asistentes de IA: la «línea» de la persona, los textos que ve el asistente y el servidor. |
| `demo/red-de-prueba.ts` | Buzón y teléfono de mamá simulados, para probar el complemento. |
| `demo/registrar-en-xrpl.ts` | Registra la identidad de Maxi en la red de prueba de XRP Ledger. |
| `demo/identidad-xrpl.ts` | Mamá verifica a Maxi contra el ledger y rechaza a un impostor. |
| `fixtures/ca-simulada/` | Autoridad certificadora simulada, con sus listas de revocación: la de documentos revoca el certificado de Marta (`npm run ca-simulada` la regenera). |

## Qué está verificado

- 75 pruebas automáticas, entre ellas los vectores oficiales de RFC 8032 (Ed25519), RFC 8037 (X25519) y RFC 7518 (Concat KDF).
- El complemento se probó de punta a punta con un cliente MCP real: lista las herramientas, escribe, llama y revisa mensajes contra la red de prueba. Claude Code lo detecta y se conecta (`claude mcp get vinculo`).
- La identidad `did:xrpl` se probó en la red de prueba real de XRP Ledger el 5 de noviembre de 2026. La transacción `DIDSet` quedó validada (`tesSUCCESS`) y el resolutor la leyó por JSON-RPC sin la biblioteca `xrpl`. Los mensajes fueron y volvieron, y el impostor quedó afuera. El complemento también funcionó con esa identidad.
- Ataques probados: raíz impostora, delegación falsificada, agente revocado, credencial robada, atributos inventados, mensajes repetidos (también después de renovar el agente o de reiniciar), sobres alterados y autorizaciones reutilizadas. También que un remitente no pueda imitar el formato de lo que lee el asistente, ni esquivar una revocación con su propio `reply_to`. En el nivel A: certificado revocado, lista de revocación faltante, vencida o alterada, y certificado de autenticación usado para firmar.
- Una revisión de seguridad del 6 de noviembre de 2026 encontró cinco problemas importantes y cinco observaciones menores. Todos están corregidos y tienen sus pruebas, la mayoría en `test/seguridad.test.ts`.
- El modo con Claude compila contra el SDK oficial, pero no se probó en vivo porque no había credenciales configuradas.

## Límites del prototipo

- Sin secreto hacia adelante: la versión 0.2 debería usar MLS.
- Sin voz real: la llamada es solo la señalización.
- Los niveles A y B usan una autoridad y un emisor simulados. Usar el documento real requiere un firmador PKCS#11 y la raíz nacional.
- Los buzones guardan en memoria.
- El complemento es una demostración: la billetera de Maxi vive en un archivo local (`datos/`), no en un teléfono, y el agente de mamá es simulado.
- La identidad en la XRP Ledger está en la red de prueba, que se reinicia cada tanto. La cuenta XRPL tiene una clave propia, distinta de la de Vínculo; en un teléfono real, las dos vivirían en la billetera. XLS-40 no fija ni el número de cada red ni una forma compacta: las dos son decisiones del perfil Vínculo.
- Es un prototipo de investigación: no tiene auditoría de seguridad.
- El nivel A comprueba la revocación con listas (CRL) completas; no admite OCSP ni listas delta o particionadas. Las listas de la autoridad simulada duran años; las reales duran días y hay que descargarlas de nuevo antes de que venzan.

## Licencia

Vínculo es un estándar abierto. El código y la especificación se publican con la licencia [Apache-2.0](LICENSE): cualquiera puede usarlos, modificarlos e implementarlos, siempre que conserve el aviso de autoría. Quien contribuya con código otorga además una licencia de las patentes que lo cubran, para que nadie pueda cerrar el protocolo después.

Copyright 2026 Maximiliano Rovelli.
