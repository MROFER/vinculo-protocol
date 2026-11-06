#!/usr/bin/env bash
# Genera una autoridad certificadora SIMULADA para probar el nivel A sin un documento real.
# Estructura: raíz -> autoridad de documentos -> certificados de titulares de prueba.
# Además crea una "raíz impostora" con el mismo nombre que la raíz y otra clave, para las pruebas negativas,
# y las listas de revocación (CRL) de cada autoridad: la de documentos revoca el certificado de Marta.
# Nada de esto tiene valor fuera del prototipo.
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash en Windows: no convertir "/C=UY/..." en rutas

DESTINO="$(cd "$(dirname "$0")/.." && pwd)/fixtures/ca-simulada"
mkdir -p "$DESTINO"
cd "$DESTINO"
rm -f ./*.pem ./*.key ./*.crl

cat > req.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = sin uso
[raiz]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

cat > ext.cnf <<'EOF'
[intermedia]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[titular]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[autenticacion]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF

RAIZ="/C=UY/O=Simulacion Vinculo/CN=Autoridad Certificadora Raiz (SIMULADA)"
INTERMEDIA="/C=UY/O=Simulacion Vinculo/CN=Autoridad Certificadora de Documentos (SIMULADA)"

openssl req -x509 -config req.cnf -extensions raiz -newkey rsa:2048 -nodes \
  -keyout raiz.key -out raiz.pem -days 3650 -subj "$RAIZ" 2>/dev/null

openssl req -new -config req.cnf -newkey rsa:2048 -nodes \
  -keyout intermedia.key -out intermedia.csr -subj "$INTERMEDIA" 2>/dev/null
openssl x509 -req -in intermedia.csr -CA raiz.pem -CAkey raiz.key -CAcreateserial \
  -out intermedia.pem -days 3000 -extfile ext.cnf -extensions intermedia 2>/dev/null

titular() { # $1 = archivo, $2 = sujeto, $3 = perfil (titular: firma; autenticacion: solo autenticación)
  openssl req -new -config req.cnf -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "$2" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA intermedia.pem -CAkey intermedia.key -CAcreateserial \
    -out "$1.pem" -days 1825 -extfile ext.cnf -extensions "${3:-titular}" 2>/dev/null
}
titular maxi "/C=UY/CN=MAXI EJEMPLO (PRUEBA)/serialNumber=DNI-12345672"
titular marta "/C=UY/CN=MARTA EJEMPLO (PRUEBA)/serialNumber=DNI-23456783"
# El documento real trae dos certificados: el de autenticación no sirve para firmar una vinculación.
titular maxi-autenticacion "/C=UY/CN=MAXI EJEMPLO (PRUEBA)/serialNumber=DNI-12345672" autenticacion

# Misma identidad que la raíz, otra clave: una cadena firmada por ella no debe validar.
openssl req -x509 -config req.cnf -extensions raiz -newkey rsa:2048 -nodes \
  -keyout impostora.key -out raiz-impostora.pem -days 3650 -subj "$RAIZ" 2>/dev/null

crl() { # $1 = autoridad (raiz | intermedia), $2 = salida, $3 = vigencia (opción de openssl ca), después: certificados revocados
  local autoridad="$1" salida="$2" vigencia="$3"
  shift 3
  rm -rf "base-$autoridad"
  mkdir -p "base-$autoridad"
  : > "base-$autoridad/index.txt"
  echo 1000 > "base-$autoridad/crlnumber"
  cat > "base-$autoridad/ca.cnf" <<EOF
[ca]
default_ca = autoridad
[autoridad]
database = base-$autoridad/index.txt
crlnumber = base-$autoridad/crlnumber
default_md = sha256
EOF
  for revocado in "$@"; do
    openssl ca -config "base-$autoridad/ca.cnf" -keyfile "$autoridad.key" -cert "$autoridad.pem" \
      -revoke "$revocado" -crl_reason keyCompromise 2>/dev/null
  done
  # shellcheck disable=SC2086 # la vigencia son dos palabras: opción y valor
  openssl ca -config "base-$autoridad/ca.cnf" -keyfile "$autoridad.key" -cert "$autoridad.pem" \
    -gencrl $vigencia -out "$salida" 2>/dev/null
}
# Vigentes mientras lo esté cada autoridad. En la realidad duran días y se descargan de nuevo antes de vencer.
crl raiz raiz.crl "-crldays 3650"
crl intermedia intermedia.crl "-crldays 3000" marta.pem
# Vencida a un segundo de emitida, para la prueba que exige una lista vigente.
crl intermedia intermedia-vencida.crl "-crlsec 1"

# Las claves de las autoridades no se guardan; las de los titulares simulan el chip del documento.
rm -rf raiz.key intermedia.key impostora.key ./*.csr ./*.srl req.cnf ext.cnf base-raiz base-intermedia
ls -1
