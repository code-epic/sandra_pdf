# sandra_pdf

Caja de herramientas PDF del ecosistema Sandra: procesa, audita y manipula
archivos PDF en una sola CLI.

## Operaciones

| Flag | Operación |
|------|-----------|
| `-p, --pages "1-3,5,8-10"` | Extracción de páginas (rangos, listas, mixto, abierto `5-`) |
| `--merge` (con `-i a.pdf,b.pdf,...`) | Unión de PDFs en orden |
| `--grayscale` | Conversión de color a DeviceGray (texto + imágenes RGB/CMYK/ICC) |
| `--optimize` | Limpieza pdfcpu (streams huérfanos, dedup de fuentes/imágenes) |
| `--set-meta K=V` / `--meta-*` | Metadata (Title, Author, Subject, Keywords, Creator) |
| `--audit` | Auditoría de seguridad (JS, OpenAction, Launch, EmbeddedFiles, AA, ...) |
| `--info` | Información: tamaño, páginas, versión, metadata |
| `--sign-cert` | Firma digital (adbe.pkcs7.detached) |
| `--json` | Salida JSON para `--audit` e `--info` |

El pipeline aplica las etapas en orden: pages/merge → grayscale → optimize →
metadata → firma → audit/info sobre el documento final.

## Build

```bash
go build -o sandra_pdf .
```

La versión se inyecta en build con `-ldflags`:

```bash
go build -trimpath -ldflags "-s -w \
  -X github.com/code-epic/sandra_pdf/cmd.appVersion=1.2.3 \
  -X github.com/code-epic/sandra_pdf/cmd.commit=$(git rev-parse --short HEAD) \
  -X github.com/code-epic/sandra_pdf/cmd.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" .
./sandra_pdf --version
```

## Instalación

Cada tag `v*` publica binarios y paquetes vía GitHub Actions
(`.github/workflows/release.yml`):

```bash
# Debian / Ubuntu
sudo dpkg -i sandra_pdf_0.1.0_amd64.deb

# RHEL / CentOS / Fedora / Rocky
sudo rpm -i sandra_pdf-0.1.0-1.x86_64.rpm

# Tarball estático (cualquier Linux/macOS)
tar xzf sandra_pdf-0.1.0-linux-amd64.tar.gz
sudo install -m 0755 sandra_pdf /usr/local/bin/
```

## Uso

```bash
# extraer páginas
sandra_pdf -i entrada.pdf -p 1-3,7 -o salida.pdf

# escala de grises + optimización
sandra_pdf -i entrada.pdf --grayscale --optimize -o salida.pdf

# metadata
sandra_pdf -i entrada.pdf --meta-title "Informe Q3" --meta-author "BDT" -o salida.pdf

# auditoría de seguridad
sandra_pdf -i entrada.pdf --audit
sandra_pdf -i entrada.pdf --audit --json

# información
sandra_pdf -i entrada.pdf --info

# unir
sandra_pdf -i a.pdf,b.pdf,c.pdf --merge -o unido.pdf

# firmar (PEM)
sandra_pdf -i entrada.pdf --sign-cert cert.pem --sign-key clave.pem \
  --sign-name "Odin" --sign-reason "Aprobación" -o firmado.pdf

# firma visible con imagen
sandra_pdf -i entrada.pdf --sign-cert cert.pem --sign-key clave.pem \
  --sign-visible --sign-page 1 --sign-rect "350,50,560,100" \
  --sign-image firma.png -o firmado.pdf
```

## Firmas digitales

Formatos de certificado soportados:

- **PEM** (`--sign-cert cert.pem --sign-key clave.pem`): certificado y clave
  separados, o bundle PEM con ambos.
- **PKCS#12 (.pfx/.p12)**: contenedor con clave embebida (`--sign-password`).

> Nota: OpenSSL 3+ genera contenedores PBES2 por defecto, que el parser
> PKCS#12 integrado (Go x/crypto) no lee. Exporte a PEM:
> `openssl pkcs12 -in f.pfx -nodes -out f.pem`.

Firmas soportadas:

- Certificación (`--sign-certify`, DocMDP) o aprobación.
- Invisible (default) o visible (`--sign-visible` + `--sign-rect` + `--sign-image`).
- La firma es siempre la última etapa: el sellado es incremental y el
  documento queda totalment firmado.

## Notas técnicas

- **Metadata hard fields**: pdfcpu sobrescribe `Producer`/`CreationDate`/
  `ModDate` en cada escritura completa; para conservarllos se aplica un patch
  incremental byte-level (objeto nuevo + xref subsection + trailer con `/Prev`).
- **Grayscale**: dos pasadas (operadores de contenido y XObjects imagen).
  Convierte FlateDecode RGB/CMYK→DeviceGray y DCTDecode vía `image/jpeg`.
  Espacios Indexed/ICC no compatibles se saltan con aviso.
- **Auditoría**: doble enfoque (walk del XRefTable + raw byte-scan de token
  como second lookout `RAW_HINT`).

## Tests

```bash
go test ./...
```
