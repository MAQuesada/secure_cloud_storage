# Estrategia de implementación — Lab 2: Secure Cloud Storage

## 1. Resumen de requisitos

- **Sistema simulado**: todo en local; el servidor guarda archivos en una carpeta (ej. `file_bin`).
- **Cliente**: interfaz visual (Streamlit) e interfaz CLI con las mismas capacidades; solo se ejecuta una a la vez.
- **Storage Server**: list, upload, download, delete de archivos (encriptados); implementado como **módulo** en el mismo proceso.
- **KMS**: gestión de material de claves; primera versión: **una Master Key (MK) por usuario**.
- **Gestión de usuarios**: simple (usuario + contraseña).
- **Requisitos funcionales**:
  - CLI básica: Client, Storage Server (list, upload, download, delete), KMS.
  - CLI avanzada: comandos, modo CSE/SSE, ayuda.
  - Paridad: lo que soporta la CLI debe soportarse en la UI.
  - **Borrado seguro de claves**: sobrescribir con ceros/datos aleatorios antes de eliminar.
  - **Carpeta compartida**: usuarios de la carpeta tienen acceso a todos sus archivos; la encriptación se mantiene.

---

## 2. Arquitectura

Todo corre en **un solo proceso**.

| Componente | Rol | Implementación |
|------------|-----|----------------|
| **Cliente** | Listar, subir, descargar, borrar archivos; elegir CSE/SSE; autenticación | Módulo Python: CLI (Click) + UI Streamlit; un entrypoint elige modo |
| **Storage Server** | Almacenar archivos encriptados; list/upload/download/delete | Módulo Python que escribe en `file_bin/` y **llama al KMS** cuando necesita claves (SSE) |
| **KMS** | Registro, login, emisión de token de sesión, entrega de MK bajo demanda (por token), borrado seguro, persistencia de usuarios y claves | Módulo Python; almacén persistente en `kms_store/` |

- El **Storage Server** no recibe claves por parámetro. Recibe **credenciales de sesión** (un **token** que genera el KMS tras el login). Cuando el Storage necesita cifrar o descifrar (modo SSE), **llama directamente a una función del KMS** pasando ese token; el KMS devuelve la MK (en memoria) para ese uso y el Storage la usa y la descarta.
- **Persistencia**: todo lo que debe sobrevivir entre ejecuciones se guarda en disco: usuarios, MK cifradas, archivos en `file_bin/`, metadatos de carpetas compartidas y de sesiones (si se desea que el token sobreviva al reinicio). Así el sistema no empieza de cero en cada corrida.

---

## 3. Flujo con token y uso del KMS desde Storage

### 3.1 Token de sesión

- Tras **login** (usuario + contraseña), el KMS:
  - Verifica la contraseña.
  - Descifra la MK del usuario (desde `kms_store/`).
  - Genera un **token de sesión** (por ejemplo, string aleatorio seguro).
  - Guarda en memoria (y opcionalmente en disco para persistir sesión) la asociación `token → (user_id, MK)` o `token → user_id` y, cuando le piden la clave por token, descifra y devuelve la MK.
- El **Cliente** recibe ese token y lo usa en todas las llamadas al Storage (y, en CSE, también lo usa para pedir la MK al KMS y cifrar/descifrar en el cliente).

### 3.2 Storage no recibe claves; usa el KMS

- El componente del Storage recibe **token de sesión** (y opcionalmente `folder_id` para carpeta compartida), no la MK ni la clave en claro.
- **CSE**: el Cliente pide al KMS la MK con `KMS.get_key_for_token(token)` (o similar), cifra/descifra localmente y envía al Storage solo **blobs ya cifrados**. El Storage solo escribe/lee en `file_bin/`; no necesita pedir claves.
- **SSE**: el Cliente envía datos en claro al Storage junto con el **token**. El Storage, cuando debe cifrar o descifrar, **llama al KMS** con ese token, por ejemplo `KMS.get_key_for_token(token)`; el KMS devuelve la MK (en memoria); el Storage la usa para cifrar al guardar o descifrar al leer, y luego la descarta (no la persiste ni la guarda en ningún lado). Así las claves nunca se pasan “por parámetro” desde el cliente al Storage; el Storage las obtiene siempre del KMS.

Ventajas de este diseño:

- Un solo lugar donde viven las claves: el KMS.
- El Storage no maneja contraseñas ni claves en sus parámetros; solo identidad de sesión (token) y datos.
- Persistencia centralizada en el KMS (usuarios, MK cifradas, y si se desea, sesiones/tokens válidos).

### 3.3 Persistencia para no empezar de cero

- **KMS** persiste en disco (por ejemplo en `kms_store/`):
  - Por usuario: `mk.enc` (MK cifrada con clave derivada de la contraseña).
  - Registro de usuarios (ej. `users.json` o SQLite: username, salt, path a `mk.enc`).
  - Opcional: sesiones activas (token → user_id) para que un token siga siendo válido tras reiniciar el proceso; si no se persisten sesiones, el usuario debe volver a hacer login en cada ejecución (los usuarios y archivos sí persisten).
- **Storage** persiste en `file_bin/` toda la estructura de archivos y blobs (por usuario y por carpeta compartida).
- Con esto, cada corrida del sistema conserva usuarios, claves (cifradas) y archivos; no se pierde nada entre ejecuciones.

---

## 4. Componentes en detalle

### 4.1 KMS (módulo)

- **Almacén**: directorio `kms_store/` (configurable por env). Por usuario:
  - `kms_store/<user_id>/mk.enc`: MK cifrada con clave derivada de la contraseña (PBKDF2 o Argon2 + AES).
- **Funciones**:
  - `register(username, password)`: crear usuario, generar MK, derivar clave desde contraseña, cifrar MK, guardar en disco.
  - `login(username, password) -> token`: verificar contraseña, descifrar MK, generar token, registrar sesión (en memoria y opcionalmente en disco).
  - `get_key_for_token(token) -> bytes`: validar token, devolver MK para ese usuario (para uso inmediato por Storage o Cliente); no persistir la MK en claro.
  - `revoke_token(token)` (opcional): invalidar sesión.
  - Borrado seguro: al eliminar usuario o rotar clave, **sobrescribir** buffer y archivo de la MK con ceros/random antes de eliminar.
- **Una MK por usuario**: se usa como clave de cifrado de archivos (o más adelante como KEK de DEKs).

### 4.2 Storage Server (módulo)

- **Entrada**: en todas las operaciones se recibe **token** (y cuando aplique `folder_id` para carpeta compartida). Nunca se recibe la MK ni la clave por parámetro.
- **Funciones** (todas con `token` como primer argumento de sesión):
  - `list(token, folder_id=None)`: resuelve user_id vía KMS si hace falta; lista archivos del usuario o de la carpeta compartida en `file_bin/`.
  - `upload(token, file_id, data, folder_id=None)`: en **CSE**, `data` ya viene cifrado; en **SSE**, `data` es en claro y el Storage llama a `KMS.get_key_for_token(token)` para obtener la MK, cifra `data` y escribe el blob en `file_bin/`.
  - `download(token, file_id, folder_id=None)`: en **CSE**, devuelve el blob; el cliente descifra. En **SSE**, el Storage lee el blob, pide la MK al KMS con el token, descifra y devuelve datos en claro.
  - `delete(token, file_id, folder_id=None)`: borra el blob (y metadata si existe).
- Estructura en disco: `file_bin/<user_id>/` (archivos propios) y `file_bin/shared/<folder_id>/` (carpetas compartidas). El Storage usa el KMS para resolver token → user_id y para obtener MK en SSE; para carpetas compartidas, el KMS puede exponer también una función del tipo `get_folder_key(token, folder_id)` (FK cifrada con la MK del usuario).

### 4.3 Cliente (lógica + CLI + Streamlit)

- **Login**: llama a `KMS.login(username, password)` y guarda el **token** en estado de sesión (CLI o Streamlit).
- **CSE**: antes de upload pide `KMS.get_key_for_token(token)`, cifra el archivo, llama a `Storage.upload(token, ...)` con los bytes ya cifrados. En download, recibe el blob del Storage, pide la MK al KMS, descifra y muestra/guarda.
- **SSE**: sube/descarga llamando a `Storage.upload` / `Storage.download` con datos en claro y el mismo token; el Storage se encarga de pedir la MK al KMS y cifrar/descifrar.
- Paridad: toda operación disponible en CLI debe estar en la UI (list, upload, download, delete, modo CSE/SSE, carpetas compartidas).

---

## 5. Modelo de datos y cifrado

### 5.1 Usuarios y autenticación

- **Registro**: `username` + `password` → KMS crea usuario, genera MK, la cifra con clave derivada de `password` y persiste en `kms_store/<user>/`.
- **Login**: `username` + `password` → KMS verifica, descifra la MK, genera **token** y lo devuelve. El cliente usa ese token en todas las llamadas al Storage y al KMS (para obtener MK en CSE o para que el Storage la pida en SSE).

### 5.2 CSE vs SSE

- **CSE**: el Cliente obtiene la MK del KMS con el token, cifra antes de enviar y descifra después de recibir. El Storage solo guarda/entrega blobs; no pide claves al KMS.
- **SSE**: el Cliente envía datos en claro al Storage con el token. El Storage llama a `KMS.get_key_for_token(token)` para cifrar al guardar y descifrar al leer; no recibe nunca la clave por parámetro desde el cliente.

### 5.3 Estructura en disco del Storage (`file_bin/`)

```
file_bin/
  <user_id>/                    # archivos privados del usuario
    <file_id>
  shared/
    <folder_id>/                # carpeta compartida
      <file_id>
```

- En **carpeta compartida**: se usa una **clave de carpeta (FK)**; los blobs se cifran con la FK. La FK se guarda en el KMS cifrada con la MK de cada miembro. El Storage, para leer/escribir en una carpeta compartida, puede pedir al KMS `get_folder_key(token, folder_id)` y usar esa FK; el KMS resuelve el token a user_id y devuelve la FK desencriptada para ese usuario. Así el Storage sigue sin recibir claves por parámetro desde el cliente; todo pasa por el KMS con el token.

### 5.4 Carpeta compartida y cifrado

- **Objetivo**: usuarios de la carpeta tienen acceso a todos los archivos; en disco todo sigue cifrado.
- **Enfoque**: FK por carpeta compartida; archivos cifrados con FK. En el KMS se guarda la FK cifrada con la MK de cada miembro. El Storage, cuando opera en una carpeta compartida, recibe `token` + `folder_id` y pide al KMS la FK con algo como `get_folder_key(token, folder_id)`; el KMS valida que el usuario del token sea miembro y devuelve la FK; el Storage cifra/descifra y no persiste la FK más que en memoria durante la operación.

---

## 6. Borrado seguro de claves

- En el **KMS**, al eliminar un usuario o rotar clave:
  - Cargar el blob de la MK en un buffer.
  - Sobrescribir el buffer con `os.urandom(len(buffer))` o ceros.
  - Sobrescribir el archivo en disco con ese buffer (abrir en modo binario, escribir, flush, cerrar).
  - Luego eliminar el archivo o la carpeta del usuario.
- No dejar la MK en memoria más tiempo del necesario; después de usarla, sobrescribir el buffer antes de liberar.
- Helpers reutilizables: `secure_zero(buf: bytearray)` y `secure_overwrite_file(path)`.

---

## 7. CLI

### 7.1 Basic CLI

- Login (KMS): `login user1 pass123` → el programa guarda el token en estado de sesión (variable de entorno, archivo de sesión en disco, o solo en memoria para esa ejecución).
- Operaciones (Cliente + Storage, siempre con token implícito o explícito):
  - `list`  
  - `upload <path> [--shared-folder <id>]`  
  - `download <file_id> [--output <path>]`  
  - `delete <file_id>`

### 7.2 Advanced CLI

- **Modo CSE/SSE**: `--mode cse` o `--mode sse` (global o por comando).
- Comandos adicionales: carpeta compartida (create, list, invite), `help` por comando y general.

Ejemplo:

```bash
secure-cloud-storage login user1 pass123
secure-cloud-storage --mode sse list
secure-cloud-storage --mode sse upload ./file.txt
secure-cloud-storage shared create
secure-cloud-storage help
```

---

## 8. Interfaz visual (Streamlit)

- Misma funcionalidad que la CLI: listar, subir, descargar, eliminar; modo CSE/SSE; carpetas compartidas.
- Solo se ejecuta **o** la CLI **o** la UI. Tras login se guarda el token (en memoria o en archivo de sesión) y se usan las mismas funciones de Storage y KMS que en la CLI.
- Flujo: pantalla de login → token guardado → pantalla principal con lista de archivos, upload/delete/download y opciones de carpeta compartida y modo CSE/SSE.

---

## 9. Orden de implementación sugerido

1. **Config y estructura**
   - Rutas `file_bin/`, `kms_store/` en config (o `.env`). Dependencias: `cryptography`, `streamlit`, `click`.

2. **KMS**
   - Persistencia: `kms_store/`, usuarios (JSON o SQLite), `mk.enc` por usuario.
   - `register`, `login` → devolver **token**; almacén en memoria (y opcionalmente en disco) token → user_id / MK.
   - `get_key_for_token(token)` para uso por Storage y Cliente.
   - Borrado seguro: `secure_zero` y sobrescritura de archivos de claves antes de borrar.

3. **Storage (módulo)**
   - API con **token** (y `folder_id` cuando aplique): `list(token, ...)`, `upload(token, ...)`, `download(token, ...)`, `delete(token, ...)`.
   - En SSE: llamar a `KMS.get_key_for_token(token)` (y para carpetas compartidas `KMS.get_folder_key(token, folder_id)`) para cifrar/descifrar; no recibir nunca la clave por parámetro.
   - Estructura en disco en `file_bin/<user_id>/` y `file_bin/shared/<folder_id>/`.

4. **Cliente (lógica)**
   - Login → token; CSE: obtener MK del KMS con token y cifrar/descifrar; SSE: enviar datos en claro al Storage con token.
   - Integrar con Storage y con carpeta compartida (FK en KMS, Storage pide FK por token + folder_id).

5. **CLI básica y avanzada**
   - Comandos: login, list, upload, download, delete; `--mode cse|sse`; shared create/list; help.

6. **Streamlit**
   - Mismas operaciones que la CLI usando el mismo token y las mismas funciones de Storage/KMS.

7. **Carpeta compartida (completa)**
   - FK por carpeta en KMS; miembros; `get_folder_key(token, folder_id)`; Storage usa FK en upload/download para blobs en `file_bin/shared/<folder_id>/`.

---

## 10. Dependencias (`pyproject.toml`)

```toml
dependencies = [
    "python-dotenv>=1.0",
    "cryptography>=42.0",
    "streamlit>=1.28",
    "click>=8.1",
]
```
