from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from werkzeug.utils import secure_filename
from flask import jsonify
from flask_wtf import CSRFProtect
from flask_talisman import Talisman
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Reemplaza por una segura
#csrf = CSRFProtect(app)#
#Talisman(app, content_security_policy=None)#  # o define tu política CSP
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20 MB

app.config['SESSION_COOKIE_HTTPONLY'] = True        # Evita acceso a cookies vía JavaScript
app.config['SESSION_COOKIE_SECURE'] = False          # Cuando tenga HTTPS o este en produccion debo poner True para seguridad de cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'       # Previene CSRF (usa 'Strict' o 'Lax' según tu caso)

UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'png', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Asegurarse de que la carpeta exista
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Función para validar extensiones permitidas
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

usuarios = []

@app.errorhandler(400)
def handle_csrf_error(e):
    if "The CSRF token is missing." in str(e) or "CSRF token" in str(e):
        flash("Error de seguridad: Token CSRF inválido o inexistente.", "danger")
        return redirect(url_for('login'))  # O la página que prefieras
    return str(e), 400

@app.errorhandler(413)
def too_large(e):
    flash("El archivo excede el tamaño máximo permitido (16 MB).", "danger")
    return redirect(request.referrer or url_for('tareas'))

def init_db():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()

        # Borrar tablas si existen
        c.execute("DROP TABLE IF EXISTS reunion_participantes")
        c.execute("DROP TABLE IF EXISTS reuniones")
        c.execute("DROP TABLE IF EXISTS tareas")
        c.execute("DROP TABLE IF EXISTS usuarios")
        c.execute("DROP TABLE IF EXISTS login_intentos")  # Asegura recreación

        # Crear tabla usuarios
        c.execute('''
            CREATE TABLE usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre_completo TEXT,
                usuario TEXT UNIQUE,
                correo TEXT,
                departamento TEXT,
                clave TEXT,
                rol TEXT
            )
        ''')

        # Crear tabla tareas
        c.execute('''
            CREATE TABLE tareas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titulo TEXT,
                fecha TEXT,
                descripcion TEXT,
                archivo TEXT,
                usuario_id INTEGER,
                revisada INTEGER DEFAULT 0,
                FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
            )
        ''')

        # Crear tabla reuniones
        c.execute('''
            CREATE TABLE reuniones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titulo TEXT,
                fecha TEXT,
                hora TEXT,
                descripcion TEXT,
                creador_id INTEGER,
                FOREIGN KEY(creador_id) REFERENCES usuarios(id)
            )
        ''')

        # Crear tabla reunion_participantes
        c.execute('''
            CREATE TABLE reunion_participantes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reunion_id INTEGER,
                usuario_id INTEGER,
                FOREIGN KEY(reunion_id) REFERENCES reuniones(id),
                FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
            )
        ''')

        # Crear tabla login_intentos
        c.execute('''
            CREATE TABLE login_intentos (
                usuario TEXT PRIMARY KEY,
                intentos INTEGER DEFAULT 0,
                bloqueado_hasta TEXT
            )
        ''')

        # Crear usuarios administradores por defecto
        from werkzeug.security import generate_password_hash

        admin1 = (
            'Informatica',
            'INFO.ADMIN',
            'soporte@municipalidadgraneros.cl',
            'Informatica',
            generate_password_hash('inf.1234'),
            'admin'
        )

        admin2 = (
            'Marcelo Miñañir',
            'M.MIÑAÑIR',
            'marcelo.minanir@municipalidadgraneros.cl',
            'Alcaldia',
            generate_password_hash('admin.1234'),
            'admin'
        )

        usuario = (
            'Ivan Jaramillo',
            'I.JARAMILLO',
            'soporte@municipalidadgraneros.cl',
            'Informatica',
            generate_password_hash('123456'),
            'usuario'
        )    
        
        c.execute('''
            INSERT INTO usuarios (nombre_completo, usuario, correo, departamento, clave, rol)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', admin1)

        c.execute('''
            INSERT INTO usuarios (nombre_completo, usuario, correo, departamento, clave, rol)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', admin2)

        c.execute('''
            INSERT INTO usuarios (nombre_completo, usuario, correo, departamento, clave, rol)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', usuario)

        conn.commit()

init_db()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/agregar_usuario', methods=['GET', 'POST'])
def agregar_usuarios():
    if request.method == 'POST':
        nombre_completo = request.form['nombre_completo']
        usuario = request.form['usuario']
        correo = request.form['correo']
        departamento = request.form['departamento']
        rol = request.form['rol']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('agregar_usuarios'))

        hashed_password = generate_password_hash(password)

        try:
            with sqlite3.connect('database.db') as conn:
                c = conn.cursor()
                c.execute('''
                    INSERT INTO usuarios (nombre_completo, usuario, correo, departamento, clave, rol)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (nombre_completo, usuario, correo, departamento, hashed_password, rol))
                conn.commit()
                flash('Usuario agregado correctamente.', 'success')
                return redirect(url_for('gestion_usuarios'))
        except sqlite3.IntegrityError:
            flash('El nombre de usuario ya existe.', 'danger')
            return redirect(url_for('agregar_usuarios'))

    return render_template('agregar_usuarios.html')

from datetime import datetime, timedelta

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        clave = request.form['clave']
        now = datetime.now()

        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute("SELECT intentos, bloqueado_hasta FROM login_intentos WHERE usuario = ?", (usuario,))
            intento = c.fetchone()

            if intento:
                intentos, bloqueado_hasta = intento
                if bloqueado_hasta:
                    bloqueado_hasta_dt = datetime.strptime(bloqueado_hasta, "%Y-%m-%d %H:%M:%S.%f")
                    if bloqueado_hasta_dt > now:
                        tiempo_restante = int((bloqueado_hasta_dt - now).total_seconds())
                        flash(f"Cuenta bloqueada. Intenta de nuevo en {tiempo_restante} segundos.", "danger")
                        return render_template('login.html')

            c.execute("SELECT id, usuario, nombre_completo, clave, rol FROM usuarios WHERE usuario = ?", (usuario,))
            user = c.fetchone()

            if user and check_password_hash(user[3], clave):
                session['usuario_id'] = user[0]
                session['usuario'] = user[1]
                session['nombre_completo'] = user[2]
                session['rol'] = user[4]
                flash(f"Bienvenido, {user[2]}!", "success")

                c.execute("DELETE FROM login_intentos WHERE usuario = ?", (usuario,))
                conn.commit()

                return redirect(url_for('bienvenida'))
            else:
                if intento:
                    intentos += 1
                    if intentos >= 5:
                        bloqueado_hasta_nuevo = now + timedelta(minutes=1)
                        bloqueado_hasta_str = bloqueado_hasta_nuevo.strftime("%Y-%m-%d %H:%M:%S.%f")
                        c.execute("UPDATE login_intentos SET intentos = ?, bloqueado_hasta = ? WHERE usuario = ?",
                                  (intentos, bloqueado_hasta_str, usuario))
                        flash("Demasiados intentos fallidos. Cuenta bloqueada por 1 minuto.", "danger")
                    else:
                        c.execute("UPDATE login_intentos SET intentos = ? WHERE usuario = ?", (intentos, usuario))
                        restantes = 5 - intentos
                        flash(f"Usuario o contraseña incorrectos.", "danger")
                else:
                    c.execute("INSERT INTO login_intentos (usuario, intentos, bloqueado_hasta) VALUES (?, ?, ?)",
                              (usuario, 1, None))
                    flash("Usuario o contraseña incorrectos.", "danger")

                conn.commit()

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Has cerrado sesión correctamente.", "success")
    return redirect(url_for('login'))

@app.route('/bienvenida')
def bienvenida():
    if 'usuario_id' not in session:
        flash("Primero debes iniciar sesión.", "warning")
        return redirect(url_for('login'))
    
    return render_template('bienvenida.html', nombre=session.get('nombre_completo'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre_completo = request.form['nombre_completo']
        usuario = request.form['usuario']
        correo = request.form['correo']
        departamento = request.form['departamento']
        clave = request.form['clave']
        confirmar_clave = request.form['confirmar_clave']

        if clave != confirmar_clave:
            flash("Las contraseñas no coinciden.", "danger")
            return redirect(url_for('registro'))

        clave_hash = generate_password_hash(clave)

        try:
            with sqlite3.connect('database.db') as conn:
                c = conn.cursor()
                c.execute('''
                    INSERT INTO usuarios (nombre_completo, usuario, correo, departamento, clave, rol)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (nombre_completo, usuario, correo, departamento, clave_hash, 'usuario'))

                conn.commit()
                flash("Usuario registrado correctamente. Ahora puedes iniciar sesión.", "success")
                return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash("El nombre de usuario ya está en uso. Elige otro.", "danger")

    return render_template('registro.html')

@app.route('/gestion_usuarios')
def gestion_usuarios():
    # Verificar si el usuario está autenticado
    if 'usuario_id' not in session:
        flash("Debes iniciar sesión para acceder.", "warning")
        return redirect(url_for('login'))

    # Verificar si el rol es administrador
    if session.get('rol') != 'admin':
        flash("No tienes permisos para acceder a esta sección.", "danger")
        return redirect(url_for('bienvenida'))  # O 'panel_usuario' si aplica

    # Obtener usuarios desde la base de datos
    with sqlite3.connect('database.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, nombre_completo, usuario, correo, departamento, rol FROM usuarios")
        usuarios = c.fetchall()

    return render_template('gestion_usuarios.html', usuarios=usuarios)

@app.route('/panel')
def panel():
    # Verifica si hay sesión activa
    if 'usuario_id' not in session:
        flash("Debes iniciar sesión para acceder al panel.", "warning")
        return redirect(url_for('login'))

    # Verifica si el rol es admin
    if session.get('rol') != 'admin':
        # Simplemente redirige, sin mostrar mensaje de error
        return redirect(url_for('panel_usuario'))

    # Si pasa la validación, renderiza el panel admin
    nombre = session.get('nombre_completo', 'Administrador')
    return render_template('panel.html', nombre=nombre)

@app.route('/panel_usuario')
def panel_usuario():
    if 'rol' not in session:
        flash("Debes iniciar sesión para acceder.", "danger")
        return redirect(url_for('login'))

    if session['rol'] != 'usuario':
        flash("No tienes permisos para acceder a esta sección.", "danger")
        return redirect(url_for('panel'))

    # ✅ Simulación de tareas (puedes usar SQLite si lo deseas)
    tareas = [
        {'titulo': 'Enviar reporte', 'fecha': '2025-09-05', 'descripcion': 'Reporte mensual', 'archivo': 'reporte.pdf'},
        {'titulo': 'Revisar proyecto', 'fecha': '2025-09-06', 'descripcion': 'Proyecto Graneros 2030', 'archivo': None}
    ]

    return render_template('panel_usuario.html', tareas=tareas)

@app.route('/tareas', methods=['GET', 'POST'])
def tareas():
    if 'usuario' not in session or session.get('rol') != 'usuario':
        flash("No tienes permisos para acceder a esta sección.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        titulo = request.form['titulo']
        fecha = request.form['fecha']
        descripcion = request.form['descripcion']
        archivo = request.files['archivo']

        nombre_archivo = None
        if archivo and allowed_file(archivo.filename):
            nombre_archivo = secure_filename(archivo.filename)
            archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], nombre_archivo))

        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO tareas (usuario_id, titulo, fecha, descripcion, archivo)
                VALUES (?, ?, ?, ?, ?)
            ''', (session['usuario_id'], titulo, fecha, descripcion, nombre_archivo))
            conn.commit()

        flash("Tarea agregada correctamente", "success")
        return redirect(url_for('panel_usuario'))

    # ✅ Obtener tareas del usuario desde la base de datos
    with sqlite3.connect('database.db') as conn:
        conn.row_factory = sqlite3.Row  # Permite acceder a columnas por nombre
        c = conn.cursor()
        c.execute('SELECT * FROM tareas WHERE usuario_id = ?', (session['usuario_id'],))
        tareas_usuario = c.fetchall()

    return render_template('tareas.html', tareas=tareas_usuario)

@app.route('/mis_tareas')
def mis_tareas():
    if 'usuario_id' not in session or session.get('rol') != 'usuario':
        flash("Debes iniciar sesión como usuario para acceder a esta sección.", "danger")
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    
    # Paginación
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1

    per_page = 6  # Cantidad de tareas por página
    offset = (page - 1) * per_page

    with sqlite3.connect('database.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Total de tareas
        c.execute("SELECT COUNT(*) FROM tareas WHERE usuario_id = ?", (usuario_id,))
        total_tareas = c.fetchone()[0]
        total_pages = (total_tareas + per_page - 1) // per_page

        # Tareas con paginación
        c.execute('''
            SELECT id, titulo, fecha, descripcion, archivo 
            FROM tareas 
            WHERE usuario_id = ?
            ORDER BY fecha DESC
            LIMIT ? OFFSET ?
        ''', (usuario_id, per_page, offset))
        tareas = c.fetchall()

    return render_template(
        'mis_tareas.html',
        tareas=tareas,
        page=page,
        total_pages=total_pages
    )

@app.route('/tareas_alcalde')
def tareas_alcalde():
    if 'usuario_id' not in session or session.get('rol') != 'admin':
        flash("No tienes permisos para acceder a esta sección.", "danger")
        return redirect(url_for('login'))

    page = request.args.get('page', 1, type=int)
    tareas_por_pagina = 6
    offset = (page - 1) * tareas_por_pagina
    usuario_filtrado = request.args.get('usuario_id', type=int)

    with sqlite3.connect('database.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Obtener lista de usuarios para el filtro
        c.execute("SELECT id, nombre_completo FROM usuarios ORDER BY nombre_completo")
        usuarios = c.fetchall()

        # Contar tareas (según filtro)
        if usuario_filtrado:
            c.execute("SELECT COUNT(*) FROM tareas WHERE usuario_id = ?", (usuario_filtrado,))
        else:
            c.execute("SELECT COUNT(*) FROM tareas")
        total_tareas = c.fetchone()[0]
        total_pages = (total_tareas + tareas_por_pagina - 1) // tareas_por_pagina

        # Obtener tareas paginadas (según filtro)
        if usuario_filtrado:
            c.execute('''
                SELECT t.id, t.titulo, t.fecha, t.descripcion, t.archivo, t.revisada, u.nombre_completo 
                FROM tareas t
                JOIN usuarios u ON t.usuario_id = u.id
                WHERE t.usuario_id = ?
                ORDER BY t.fecha DESC
                LIMIT ? OFFSET ?
            ''', (usuario_filtrado, tareas_por_pagina, offset))
        else:
            c.execute('''
                SELECT t.id, t.titulo, t.fecha, t.descripcion, t.archivo, t.revisada, u.nombre_completo 
                FROM tareas t
                JOIN usuarios u ON t.usuario_id = u.id
                ORDER BY t.fecha DESC
                LIMIT ? OFFSET ?
            ''', (tareas_por_pagina, offset))

        tareas = c.fetchall()

    return render_template(
        'tareas_alcalde.html',
        tareas=tareas,
        page=page,
        total_pages=total_pages,
        usuarios=usuarios,
        usuario_filtrado=usuario_filtrado
    )

@app.route('/accion_tarea', methods=['POST'])
def accion_tarea():
    if 'usuario_id' not in session or session.get('rol') != 'admin':
        flash("No tienes permisos para realizar esta acción.", "danger")
        return redirect(url_for('login'))

    tarea_id = request.form.get('tarea_id')
    accion = request.form.get('accion')

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        
        if accion == "eliminar":
            c.execute("DELETE FROM tareas WHERE id = ?", (tarea_id,))
            flash("Tarea eliminada correctamente.", "success")

        elif accion == "revisada":
            c.execute("UPDATE tareas SET revisada = 1 WHERE id = ?", (tarea_id,))
            flash("Tarea marcada como revisada.", "info")

        conn.commit()

    return redirect(url_for('tareas_alcalde'))

@app.route('/tareas_alcalde/revisar/<int:tarea_id>', methods=['POST'])
def marcar_revisada(tarea_id):
    if 'usuario_id' not in session or session.get('rol') != 'admin':
        flash("No tienes permisos para realizar esta acción.", "danger")
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute("UPDATE tareas SET revisada= 1 WHERE id = ?", (tarea_id,))
        conn.commit()

    flash("Tarea marcada como revisada.", "success")
    return redirect(url_for('tareas_alcalde'))

@app.route('/tareas_alcalde/eliminar/<int:tarea_id>', methods=['POST'])
def eliminar_tarea(tarea_id):
    if 'usuario_id' not in session or session.get('rol') != 'admin':
        flash("No tienes permisos para realizar esta acción.", "danger")
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute("DELETE FROM tareas WHERE id = ?", (tarea_id,))
        conn.commit()

    flash("Tarea eliminada correctamente.", "success")
    return redirect(url_for('tareas_alcalde'))

@app.route('/usuarios/editar/<int:usuario_id>', methods=['GET', 'POST'])
def editar_usuario(usuario_id):
    # Validar rol admin
    if session.get('rol') != 'admin':
        flash('No tienes permisos para acceder a esta página.', 'danger')
        return redirect(url_for('panel_principal'))

    with sqlite3.connect('database.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        if request.method == 'POST':
            # Actualizar usuario con los datos del formulario
            nombre_completo = request.form['nombre_completo']
            usuario = request.form['usuario']
            correo = request.form['correo']
            departamento = request.form['departamento']
            rol = request.form.get('rol', 'usuario')  # Por defecto 'usuario'

            c.execute('''
                UPDATE usuarios
                SET nombre_completo=?, usuario=?, correo=?, departamento=?, rol=?
                WHERE id=?
            ''', (nombre_completo, usuario, correo, departamento, rol, usuario_id))
            conn.commit()

            flash('Usuario actualizado correctamente.', 'success')
            # Redirigir para evitar reenvío de formulario y mostrar flash solo después de actualizar
            return redirect(url_for('editar_usuario', usuario_id=usuario_id))

        # GET: traer datos del usuario para mostrar en formulario
        c.execute('SELECT * FROM usuarios WHERE id=?', (usuario_id,))
        usuario = c.fetchone()
        if not usuario:
            flash('Usuario no encontrado.', 'danger')
            return redirect(url_for('gestion_usuarios'))

    # Renderizar registro.html con los datos para editar, sin mostrar mensaje flash aquí
    return render_template('registro.html', usuario=usuario, editar=True)

@app.route('/usuarios/eliminar/<int:usuario_id>', methods=['POST'])
def eliminar_usuario(usuario_id):
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        # Evitar borrar usuarios admin fijos (opcional, por seguridad)
        c.execute('SELECT rol FROM usuarios WHERE id=?', (usuario_id,))
        rol = c.fetchone()
        if rol and rol[0] == 'admin':
            flash('No puedes eliminar un usuario administrador.', 'danger')
            return redirect(url_for('gestion_usuarios'))

        c.execute('DELETE FROM usuarios WHERE id=?', (usuario_id,))
        conn.commit()
        flash('Usuario eliminado correctamente.', 'success')

    return redirect(url_for('gestion_usuarios'))

@app.route('/agendar_reunion', methods=['GET', 'POST'])
def agendar_reunion():
    if 'usuario_id' not in session or session.get('rol') != 'usuario':
        flash("Debes iniciar sesión como usuario para agendar reuniones.", "danger")
        return redirect(url_for('login'))

    # Obtener todos los usuarios ordenados alfabéticamente
    with sqlite3.connect('database.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, nombre_completo FROM usuarios ORDER BY nombre_completo ASC")
        all_users = c.fetchall()

    if request.method == 'POST':
        titulo = request.form['titulo'].strip()
        fecha = request.form['fecha']
        hora = request.form['hora']
        descripcion = request.form['descripcion'].strip()
        participantes = request.form.getlist('participantes')

        # Validación simple de campos requeridos
        if not titulo or not fecha or not hora or not participantes:
            flash("Por favor, completa todos los campos obligatorios.", "warning")
            return render_template('agendar_reunion.html', users=all_users)

        try:
            with sqlite3.connect('database.db') as conn:
                c = conn.cursor()

                # Insertar reunión
                c.execute('''
                    INSERT INTO reuniones (titulo, fecha, hora, descripcion, creador_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (titulo, fecha, hora, descripcion, session['usuario_id']))
                reunion_id = c.lastrowid

                # Insertar participantes
                for pid in participantes:
                    c.execute('''
                        INSERT INTO reunion_participantes (reunion_id, usuario_id)
                        VALUES (?, ?)
                    ''', (reunion_id, pid))

                conn.commit()

                flash("✅ ¡Reunión agendada con éxito!", "success")
                return redirect(url_for('mis_reuniones'))  # También puedes usar 'panel_usuario' si prefieres

        except Exception as e:
            flash("❌ Ocurrió un error al agendar la reunión. Intenta nuevamente.", "danger")
            print("Error al agendar reunión:", e)

    return render_template('agendar_reunion.html', users=all_users)

@app.route('/mis_reuniones')
def mis_reuniones():
    if 'usuario_id' not in session or session.get('rol') != 'usuario':
        flash("Debes iniciar sesión como usuario para acceder a esta sección.", "danger")
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']

    # Obtener parámetros de paginación
    page_c = int(request.args.get('page_c', 1))  # Reuniones creadas
    page_i = int(request.args.get('page_i', 1))  # Reuniones invitado
    por_pagina = 3  # Número de reuniones por página

    with sqlite3.connect('database.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        ### 1. Reuniones creadas por el usuario
        c.execute('''
            SELECT * FROM reuniones
            WHERE creador_id = ?
            ORDER BY fecha DESC
        ''', (usuario_id,))
        reuniones_creadas = c.fetchall()

        creadas = []
        for reunion in reuniones_creadas:
            c.execute('''
                SELECT u.nombre_completo
                FROM reunion_participantes rp
                JOIN usuarios u ON rp.usuario_id = u.id
                WHERE rp.reunion_id = ?
            ''', (reunion['id'],))
            participantes = [row['nombre_completo'] for row in c.fetchall()]
            creadas.append({
                'titulo': reunion['titulo'],
                'fecha': reunion['fecha'],
                'hora': reunion['hora'],
                'descripcion': reunion['descripcion'],
                'participantes': participantes
            })

        # Paginación de creadas
        total_c = len(creadas)
        total_pages_c = (total_c + por_pagina - 1) // por_pagina
        creadas_pag = creadas[(page_c - 1) * por_pagina : page_c * por_pagina]

        ### 2. Reuniones como invitado
        c.execute('''
            SELECT r.*, u.nombre_completo AS creador_nombre
            FROM reunion_participantes rp
            JOIN reuniones r ON rp.reunion_id = r.id
            JOIN usuarios u ON r.creador_id = u.id
            WHERE rp.usuario_id = ? AND r.creador_id != ?
            ORDER BY r.fecha DESC
        ''', (usuario_id, usuario_id))
        reuniones_invitado = c.fetchall()

        invitado = []
        for reunion in reuniones_invitado:
            invitado.append({
                'titulo': reunion['titulo'],
                'fecha': reunion['fecha'],
                'hora': reunion['hora'],
                'descripcion': reunion['descripcion'],
                'creador_nombre': reunion['creador_nombre']
            })

        # Paginación de invitado
        total_i = len(invitado)
        total_pages_i = (total_i + por_pagina - 1) // por_pagina
        invitado_pag = invitado[(page_i - 1) * por_pagina : page_i * por_pagina]

    return render_template(
        'mis_reuniones.html',
        creadas=creadas_pag,
        invitado=invitado_pag,
        page_c=page_c,
        total_pages_c=total_pages_c,
        page_i=page_i,
        total_pages_i=total_pages_i
    )

@app.route('/agendar_reunion_admin', methods=['GET', 'POST'])
def agendar_reunion_admin():
    if 'usuario_id' not in session or session.get('rol') != 'admin':
        flash("Debes iniciar sesión como administrador para acceder a esta sección.", "danger")
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, nombre_completo FROM usuarios")
        usuarios = c.fetchall()

        if request.method == 'POST':
            titulo = request.form['titulo']
            fecha = request.form['fecha']
            hora = request.form['hora']
            descripcion = request.form['descripcion']
            participantes = request.form.getlist('participantes')
            creador_id = session['usuario_id']

            # Insertar reunión
            c.execute('''
                INSERT INTO reuniones (titulo, fecha, hora, descripcion, creador_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (titulo, fecha, hora, descripcion, creador_id))
            reunion_id = c.lastrowid

            # Insertar participantes
            for participante_id in participantes:
                c.execute('''
                    INSERT INTO reunion_participantes (reunion_id, usuario_id)
                    VALUES (?, ?)
                ''', (reunion_id, participante_id))

            conn.commit()
            flash("Reunión agendada exitosamente.", "success")
            return redirect(url_for('panel'))

    return render_template('agendar_reunion_admin.html', usuarios=usuarios)

@app.route('/reuniones_alcalde')
def reuniones_alcalde():
    if 'usuario_id' not in session or session.get('rol') != 'admin':
        flash("Debes iniciar sesión como administrador.", "danger")
        return redirect(url_for('login'))

    admin_id = session['usuario_id']

    # Obtener los parámetros de paginación
    page_creadas = int(request.args.get('page_creadas', 1))
    page_invitado = int(request.args.get('page_invitado', 1))
    per_page = 3  # Cantidad de reuniones por página

    with sqlite3.connect('database.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Total de reuniones creadas
        c.execute('SELECT COUNT(*) FROM reuniones WHERE creador_id = ?', (admin_id,))
        total_creadas = c.fetchone()[0]

        # Paginación: reuniones creadas
        offset_creadas = (page_creadas - 1) * per_page
        c.execute('''
            SELECT * FROM reuniones
            WHERE creador_id = ?
            ORDER BY fecha DESC
            LIMIT ? OFFSET ?
        ''', (admin_id, per_page, offset_creadas))
        reuniones_creadas = c.fetchall()

        creadas = []
        for reunion in reuniones_creadas:
            c.execute('''
                SELECT u.nombre_completo
                FROM reunion_participantes rp
                JOIN usuarios u ON rp.usuario_id = u.id
                WHERE rp.reunion_id = ?
            ''', (reunion['id'],))
            participantes = [row['nombre_completo'] for row in c.fetchall()]
            creadas.append({
                'titulo': reunion['titulo'],
                'fecha': reunion['fecha'],
                'hora': reunion['hora'],
                'descripcion': reunion['descripcion'],
                'participantes': participantes
            })

        # Total reuniones invitado
        c.execute('''
            SELECT COUNT(*)
            FROM reunion_participantes rp
            JOIN reuniones r ON rp.reunion_id = r.id
            WHERE rp.usuario_id = ? AND r.creador_id != ?
        ''', (admin_id, admin_id))
        total_invitado = c.fetchone()[0]

        # Paginación: reuniones donde fue invitado
        offset_invitado = (page_invitado - 1) * per_page
        c.execute('''
            SELECT r.*, u.nombre_completo AS creador_nombre
            FROM reunion_participantes rp
            JOIN reuniones r ON rp.reunion_id = r.id
            JOIN usuarios u ON r.creador_id = u.id
            WHERE rp.usuario_id = ? AND r.creador_id != ?
            ORDER BY r.fecha DESC
            LIMIT ? OFFSET ?
        ''', (admin_id, admin_id, per_page, offset_invitado))
        reuniones_invitado = c.fetchall()

        invitado = []
        for reunion in reuniones_invitado:
            invitado.append({
                'titulo': reunion['titulo'],
                'fecha': reunion['fecha'],
                'hora': reunion['hora'],
                'descripcion': reunion['descripcion'],
                'creador_nombre': reunion['creador_nombre']
            })

    return render_template(
        'reuniones_alcalde.html',
        creadas=creadas,
        invitado=invitado,
        page_creadas=page_creadas,
        total_creadas=total_creadas,
        page_invitado=page_invitado,
        total_invitado=total_invitado,
        per_page=per_page
    )

@app.route('/calendario/usuario')
def calendario_usuarios():
    if 'usuario_id' not in session:
        flash("Debes iniciar sesión.", "warning")
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']

    with sqlite3.connect('database.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Tareas
        c.execute("SELECT titulo, fecha, descripcion FROM tareas WHERE usuario_id = ?", (usuario_id,))
        tareas = c.fetchall()

        # Reuniones
        c.execute("""
            SELECT r.titulo, r.fecha, r.descripcion
            FROM reuniones r
            JOIN reunion_participantes rp ON r.id = rp.reunion_id
            WHERE rp.usuario_id = ?
        """, (usuario_id,))
        reuniones = c.fetchall()

    eventos = []

    for tarea in tareas:
        eventos.append({
            "title": f"✅ {tarea['titulo']}",
            "start": tarea['fecha'],
            "description": tarea['descripcion'],
            "color": "#27ae60"
        })

    for reunion in reuniones:
        eventos.append({
            "title": f"📅 {reunion['titulo']}",
            "start": reunion['fecha'],
            "description": reunion['descripcion'],
            "color": "#2980b9"
        })

    return render_template("calendario_usuarios.html", eventos=eventos)

if __name__ == '__main__':
    app.run(host='192.168.1.214', port=5000)
