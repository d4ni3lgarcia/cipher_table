import hashlib
import sqlite3
import os
import base64
import sys
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# --- Variables de Configuración ---
# DB_FILE ahora se pasa como argumento
ITERATIONS = 100_000 # Iteraciones para PBKDF2HMAC, influye en la seguridad y el rendimiento de derivación de clave

# --- Funciones de Criptografía ---
def derivar_clave(clave_maestra: bytes, salt: bytes) -> bytes:
    """Deriva una clave de cifrado segura a partir de la clave maestra y un salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # 32 bytes para una clave AES de 256 bits, requerida por Fernet
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(clave_maestra))

def cifrar_dato(dato: str, clave_cifrado: bytes) -> str:
    """Cifra una cadena de texto usando Fernet."""
    f = Fernet(clave_cifrado)
    return f.encrypt(dato.encode()).decode() # Codifica a bytes antes de cifrar, decodifica a str para almacenar

def descifrar_dato(dato_cifrado: str, clave_cifrado: bytes) -> str:
    """Descifra una cadena de texto cifrada con Fernet."""
    f = Fernet(clave_cifrado)
    try:
        return f.decrypt(dato_cifrado.encode()).decode() # Codifica a bytes antes de descifrar, decodifica a str
    except Exception as e:
        # print(f"Error al descifrar: {e}") # Para depuración
        return "ERROR AL DESCIFRAR"

# --- Funciones de la Base de Datos ---
def inicializar_db(db_file: str, column_headers: list = None):
    """
    Crea las tablas 'config' y 'data' si no existen.
    La tabla 'data' se configura con encabezados dinámicos solo si se proporciona 'column_headers'.
    """
    with sqlite3.connect(db_file) as con:
        cursor = con.cursor()
        
        # Tabla para la configuración (salt y hash de la clave maestra, y los encabezados de las columnas)
        sql_config = '''CREATE TABLE IF NOT EXISTS config (
                            id INTEGER PRIMARY KEY,
                            salt BLOB NOT NULL,
                            master_key_hash TEXT NOT NULL,
                            column_headers TEXT NOT NULL
                        );'''
        cursor.execute(sql_config)

        # Si se proporcionan encabezados, creamos o recreamos la tabla 'data' con esos encabezados.
        # Esto solo ocurre en la fase 'create' inicial.
        if column_headers:
            # Drop the table if it exists to allow re-creation with new columns
            cursor.execute("DROP TABLE IF EXISTS data;")
            
            columns_sql = ", ".join([f'"{header}" TEXT NOT NULL' for header in column_headers])
            sql_data = f'''CREATE TABLE data (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                {columns_sql}
                            );'''
            cursor.execute(sql_data)
        
        con.commit()

def obtener_configuracion_maestra(db_file: str):
    """Recupera el salt, el hash de la clave maestra y los encabezados de la DB."""
    with sqlite3.connect(db_file) as con:
        cursor = con.cursor()
        cursor.execute("SELECT salt, master_key_hash, column_headers FROM config WHERE id = 1;")
        result = cursor.fetchone()
        if result:
            salt, master_key_hash, headers_str = result
            return salt, master_key_hash, headers_str.split(',') # Convertir string de headers a lista
        return None, None, None

def guardar_configuracion_maestra(db_file: str, salt: bytes, master_key_hash: str, column_headers: list):
    """Guarda el salt, el hash de la clave maestra y los encabezados en la DB."""
    headers_str = ",".join(column_headers) # Convertir lista de headers a string para almacenar
    with sqlite3.connect(db_file) as con:
        cursor = con.cursor()
        # Usamos INSERT OR REPLACE para asegurarnos de que solo haya una fila de configuración
        cursor.execute("INSERT OR REPLACE INTO config (id, salt, master_key_hash, column_headers) VALUES (?, ?, ?, ?);",
                       (1, salt, master_key_hash, headers_str))
        con.commit()

def imprimir_tabla_nativa(headers: list, data: list):
    """Imprime una tabla de datos de forma nativa en la consola."""
    if not headers:
        print("No hay columnas definidas para mostrar.")
        return

    # Calcular el ancho máximo para cada columna
    widths = [len(h) for h in headers]
    for row in data:
        for i, cell in enumerate(row):
            # Asegurarse de que el índice no esté fuera de rango para 'widths'
            if i < len(widths):
                cell_width = len(str(cell))
                if cell_width > widths[i]:
                    widths[i] = cell_width
            else:
                # Si la fila tiene más elementos que los encabezados, ajustar el ancho para los nuevos elementos
                widths.append(len(str(cell)))

    separator = "  "
    format_string = separator.join([f"{{:<{w}}}" for w in widths])

    # Imprimir encabezados
    print(format_string.format(*headers))
    # Imprimir línea separadora
    print(separator.join(["-" * w for w in widths]))

    # Imprimir datos
    if not data:
        print("No hay registros guardados en esta tabla.")
    else:
        for row in data:
            # Asegurarse de que el número de elementos en la fila coincida con el formato
            # o rellenar con espacios si es necesario.
            formatted_row = [str(cell) for cell in row]
            print(format_string.format(*formatted_row))

def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ["create", "open"]:
        print("Uso: python gestor_tablas.py create <nombre_archivo_db>")
        print("Uso: python gestor_tablas.py open <nombre_archivo_db>")
        return

    action = sys.argv[1]
    db_file = sys.argv[2]
    clave_cifrado = None
    column_headers = [] # Inicializamos vacío, se llenará según la acción

    if action == "create":
        if os.path.exists(db_file):
            print(f"Error: El archivo '{db_file}' ya existe. Use 'open' si desea abrirlo o elija otro nombre.")
            return

        print(f"Creando nuevo baúl en '{db_file}'.")
        
        # 1. Definir columnas
        while True:
            try:
                num_cols = int(input("Ingrese el número de columnas para su tabla: "))
                if num_cols > 0:
                    break
                else:
                    print("El número de columnas debe ser mayor que cero.")
            except ValueError:
                print("Entrada inválida. Por favor, ingrese un número entero.")
        
        for i in range(num_cols):
            while True:
                header = input(f"Ingrese el título para la columna {i+1}: ").strip()
                if header and header not in column_headers: # Asegurarse de que no esté vacío y sea único
                    column_headers.append(header)
                    break
                elif not header:
                    print("El título de la columna no puede estar vacío.")
                else:
                    print("Ese título ya ha sido usado. Por favor, ingrese uno diferente.")
        
        # 2. Configurar Clave Maestra
        print("\nAhora, configure su Clave Maestra para el baúl.")
        clave_maestra_1 = getpass("Cree su Clave Maestra: ")
        clave_maestra_2 = getpass("Confirme su Clave Maestra: ")

        if clave_maestra_1 != clave_maestra_2 or not clave_maestra_1:
            print("Las claves no coinciden o están vacías. Saliendo.")
            return

        salt = os.urandom(16)
        hash_obj = hashlib.sha256((clave_maestra_1 + str(salt)).encode()).hexdigest()
        
        # Inicializar DB con la estructura y guardar la configuración
        inicializar_db(db_file, column_headers)
        guardar_configuracion_maestra(db_file, salt, hash_obj, column_headers)
        
        print(f"✅ Baúl '{db_file}' creado y Clave Maestra configurada de forma segura.")
        clave_cifrado = derivar_clave(clave_maestra_1.encode(), salt)

    elif action == "open":
        if not os.path.exists(db_file):
            print(f"Error: El archivo '{db_file}' no existe. Use 'create' para crearlo.")
            return
        
        inicializar_db(db_file) # Asegura que la tabla 'config' exista si el archivo es muy antiguo o vacío
        salt, hash_guardado, stored_column_headers = obtener_configuracion_maestra(db_file)

        if salt is None:
            print(f"Error: No se encontró configuración de clave maestra o columnas en '{db_file}'. "
                  "Es posible que el archivo esté corrupto o no se haya creado correctamente.")
            return

        column_headers = stored_column_headers # Recuperar los encabezados almacenados
        
        clave_maestra_ingresada = getpass("Ingrese su Clave Maestra para desbloquear: ")
        hash_ingresado = hashlib.sha256((clave_maestra_ingresada + str(salt)).encode()).hexdigest()

        if hash_ingresado != hash_guardado:
            print("❌ Clave Maestra incorrecta. Saliendo.")
            return
        
        print(f"🔑 Baúl '{db_file}' desbloqueado.")
        clave_cifrado = derivar_clave(clave_maestra_ingresada.encode(), salt)

    # --- Operaciones después del desbloqueo ---
    if clave_cifrado:
        while True:
            print("\n--- Opciones ---")
            print("1. Ver registros")
            print("2. Agregar nuevo registro")
            print("3. Salir")
            
            choice = input("Seleccione una opción: ")

            if choice == '1':
                print("\n--- Registros Guardados ---")
                with sqlite3.connect(db_file) as con:
                    cursor = con.cursor()
                    # Seleccionar todas las columnas dinámicamente
                    columns_select_sql = ", ".join([f'"{h}"' for h in column_headers])
                    # Asegurarse de que "id" siempre se incluya
                    cursor.execute(f"SELECT id, {columns_select_sql} FROM data;")
                    resultados_cifrados = cursor.fetchall()
                    
                    filas_descifradas = []
                    for row_tuple in resultados_cifrados:
                        # El primer elemento es el ID, los demás son datos cifrados
                        id_val = row_tuple[0]
                        cifrados = row_tuple[1:]
                        
                        descifrados = [id_val] # Agrega el ID primero
                        for dato_cifrado in cifrados:
                            descifrados.append(descifrar_dato(dato_cifrado, clave_cifrado))
                        filas_descifradas.append(descifrados)
                    
                    # Añadir "ID" al inicio de los encabezados para mostrarlo
                    display_headers = ["ID"] + column_headers
                    imprimir_tabla_nativa(display_headers, filas_descifradas)

            elif choice == '2':
                print("\n--- Agregar Nuevo Registro ---")
                new_row_data = []
                for header in column_headers:
                    value = input(f"Ingrese valor para '{header}': ").strip()
                    new_row_data.append(cifrar_dato(value, clave_cifrado))
                
                with sqlite3.connect(db_file) as con:
                    cursor = con.cursor()
                    placeholders = ", ".join(["?" for _ in column_headers])
                    columns_insert_sql = ", ".join([f'"{h}"' for h in column_headers])
                    sql = f'INSERT INTO data ({columns_insert_sql}) VALUES ({placeholders});'
                    cursor.execute(sql, tuple(new_row_data))
                    con.commit()
                print("✅ Registro agregado exitosamente (todos los campos cifrados).")

            elif choice == '3':
                print("Saliendo del baúl.")
                break
            else:
                print("Opción no válida. Por favor, intente de nuevo.")

if __name__ == "__main__":
    main()