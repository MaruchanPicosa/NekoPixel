from flask import Flask, render_template, request, redirect, url_for, session, flash,send_file
from pymongo import MongoClient
import bcrypt
from werkzeug.utils import secure_filename
from bson import ObjectId,binary
import os
import io
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_aqui' # ¡Cambia esto en producción!

# Configuración de MongoDB Atlas
# Asegúrate de que tu cadena de conexión sea correcta
client = MongoClient('mongodb+srv://zaida:5bvTAAUKVWkOCUbd@cluster0.4r084.mongodb.net/') 
try:
    # The ismaster command is cheap and does not require auth.
    client.admin.command('ismaster')
    print("MongoDB Atlas connection successful!")
except ConnectionFailure:
    print("MongoDB Atlas connection failed!")
    # Decide cómo manejar el fallo de conexión (salir, reintentar, etc.)

db = client['nekopixel'] # Nombre de tu base de datos
users_collection = db['usuarios']
posts_collection = db['publicaciones']
comunidades_collection = db['comunidades'] # Considera renombrar a 'guilds' si prefieres

# Extensiones permitidas para subida de archivos
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'mp4', 'webp'} # Añadido webp para Kirby

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Rutas para servir archivos desde MongoDB ---

@app.route('/media/<post_id>')
def serve_media(post_id):
    try:
        post = posts_collection.find_one({'_id': ObjectId(post_id)})
        if post and 'media_data' in post and post['media_data']: # Verifica que media_data no sea None
            media = post['media_data']
            return send_file(
                io.BytesIO(media['data']),
                mimetype=media['content_type'],
                as_attachment=False,
                download_name=media['filename']
            )
    except Exception as e:
        print(f"Error serving media for post {post_id}: {e}") # Log del error
    return "Archivo no encontrado", 404

@app.route('/community_media/<community_id>/<post_id>')
def serve_community_media(community_id, post_id):
    try:
        community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
        if community:
            for post in community.get('posts', []):
                 # Asegúrate de que el _id del post sea un ObjectId si lo guardaste así
                 # O compara como string si siempre lo guardas como string
                if str(post.get('_id')) == post_id and 'media_data' in post and post['media_data']:
                    media = post['media_data']
                    return send_file(
                        io.BytesIO(media['data']),
                        mimetype=media['content_type'],
                        as_attachment=False,
                        download_name=media['filename']
                    )
    except Exception as e:
        print(f"Error serving community media for post {post_id} in comm {community_id}: {e}")
    return "Archivo no encontrado", 404

@app.route('/community_banner/<community_id>')
def serve_community_banner(community_id):
    try:
        community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
        # Verifica que banner_data exista y no sea None
        if community and 'banner_data' in community and community['banner_data']: 
            banner = community['banner_data']
            return send_file(
                io.BytesIO(banner['data']),
                mimetype=banner['content_type'],
                as_attachment=False,
                download_name=banner['filename']
            )
    except Exception as e:
        print(f"Error serving banner for community {community_id}: {e}")
    # Si no hay banner o hay error, puedes devolver un 404 o una imagen placeholder
    # El HTML ya maneja el onerror, así que un 404 está bien.
    return "Banner no encontrado", 404


@app.route('/profile_pic/<username>')
def serve_profile_pic(username):
    try:
        user = users_collection.find_one({'username': username})
        # Verifica que profile_pic exista y no sea None
        if user and 'profile_pic' in user and user['profile_pic']: 
            pic = user['profile_pic']
            return send_file(
                io.BytesIO(pic['data']),
                mimetype=pic['content_type'],
                as_attachment=False,
                download_name=pic['filename']
            )
    except Exception as e:
        print(f"Error serving profile pic for user {username}: {e}")
    # Imagen predeterminada si no hay foto de perfil o hay error
    try:
        # Asegúrate que 'static/Kirby.webp' exista
        return send_file('static/img/Kirby.webp', mimetype='image/webp') 
    except FileNotFoundError:
        print("Error: Default profile picture 'static/img/Kirby.webp' not found.")
        return "Imagen predeterminada no encontrada", 404

# --- Rutas Principales de la Aplicación ---

@app.route('/')
def index():
    # Optimización: Proyectar solo los campos necesarios si la colección crece mucho
    posts = list(posts_collection.find().sort("timestamp", -1)) 
    communities = list(comunidades_collection.find({}, {"name": 1, "tags": 1})) # Solo nombre y tags

    # Convertir ObjectId a string para pasar a la plantilla
    for post in posts:
        post['_id'] = str(post['_id'])
        # Asegúrate de que los comentarios y likes estén presentes (aunque sean listas vacías)
        post['comments'] = post.get('comments', [])
        post['likes'] = post.get('likes', [])
        
    for community in communities:
        community['_id'] = str(community['_id'])
        community['tags'] = community.get('tags', []) # Asegurar que tags exista

    return render_template('index.html', posts=posts, communities=communities)

# --- Rutas Placeholder para Navegación ---
@app.route('/explore')
def explore():
    flash('La página "Explorar" aún está en construcción.', 'info')
    return redirect(url_for('index')) 

# Decorador para requerir inicio de sesión (si no lo tienes)
from functools import wraps
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Debes iniciar sesión para ver esta página.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/messages')
@login_required 
def messages():
    flash('La página "Mensajes" aún está en construcción.', 'info')
    return redirect(url_for('index'))

@app.route('/notifications')
@login_required
def notifications():
    flash('La página "Notificaciones" aún está en construcción.', 'info')
    return redirect(url_for('index'))

# --- Rutas de Autenticación y Perfil ---

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username'].strip() # Quitar espacios
        email = request.form['email'].strip().lower() # Guardar en minúsculas
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        if not username or not email or not password:
             flash('Todos los campos son requeridos', 'error')
             return redirect(url_for('registro'))
        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'error')
            return redirect(url_for('registro'))
        if users_collection.find_one({'$or': [{'username': username}, {'email': email}]}):
            flash('El nombre de usuario o correo electrónico ya está en uso', 'error')
            return redirect(url_for('registro'))
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users_collection.insert_one({
            'username': username,
            'email': email,
            'password': hashed_password,
            'created_at': datetime.utcnow(),
            'profile_pic': None # Asegurarse de que el campo exista
        })
        flash('Registro exitoso. Por favor, inicia sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('registro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username'].strip()
        password = request.form['password']

        user = users_collection.find_one({'$or': [{'username': username_or_email}, {'email': username_or_email.lower()}]})

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['username'] = user['username'] 
            return redirect(url_for('index')) 
        else:
            flash('Usuario o contraseña incorrectos', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None) 
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('index'))

@app.route('/perfil')
@login_required
def perfil():
    username = session['username']
    user = users_collection.find_one({'username': username})
    if not user:
        session.pop('username', None) # Limpiar sesión si el usuario no existe
        flash('Usuario no encontrado', 'error')
        return redirect(url_for('login'))

    # Cálculos de estadísticas (pueden ser lentos si hay muchos posts)
    total_posts = posts_collection.count_documents({'username': username})
    # Conteo de likes recibidos en todos los posts
    user_posts_ids = [post['_id'] for post in posts_collection.find({'username': username}, {'_id': 1})]
    total_likes_received = posts_collection.count_documents({'likes': username}) # Likes dados? O recibidos? Esta query es likes DADOS
    # Para likes recibidos sería más complejo, iterar o aggregation
    
    total_comments_received = 0 # Similar a likes, requiere iterar o aggregation
    for post in posts_collection.find({'username': username}):
         total_comments_received += len(post.get('comments', []))


    created_communities = list(comunidades_collection.find({'creator': username}, {"name": 1}))
    joined_communities = list(comunidades_collection.find({'members': username}, {"name": 1}))
    
    # Convertir IDs a string
    for comm in created_communities: comm['_id'] = str(comm['_id'])
    for comm in joined_communities: comm['_id'] = str(comm['_id'])

    # Evitar duplicados si el creador también está en members
    joined_community_ids = {str(c['_id']) for c in joined_communities}
    created_communities_filtered = [c for c in created_communities if str(c['_id']) in joined_community_ids]


    return render_template('perfil.html', 
                           user=user, 
                           total_posts=total_posts, 
                           total_likes=total_likes_received, # Ajustar si es necesario
                           total_comments=total_comments_received, 
                           created_communities=created_communities, 
                           joined_communities=joined_communities) # Pasar ambas listas


# Ruta para ver perfiles de *otros* usuarios
@app.route('/perfil/<username>')
def ver_perfil(username):
    if 'username' in session and session['username'] == username:
        return redirect(url_for('perfil')) # Redirige al perfil propio si es el mismo usuario

    user = users_collection.find_one({'username': username})
    if not user:
        flash('Usuario no encontrado', 'error')
        return redirect(url_for('index'))
    
    # Aquí puedes añadir la lógica para calcular estadísticas públicas del usuario
    total_posts = posts_collection.count_documents({'username': username})
    
    # Renderiza una plantilla de perfil pública (necesitas crearla: 'ver_perfil.html')
    # return render_template('ver_perfil.html', user=user, total_posts=total_posts)
    flash(f'Viendo el perfil público de {username}. (Página en construcción)', 'info')
    return redirect(url_for('index'))


@app.route('/configuracion', methods=['GET'])
@login_required
def configuracion():
    user = users_collection.find_one({'username': session['username']})
    if not user:
        return redirect(url_for('login')) # Si no encuentra al usuario, redirige a login
    return render_template('configuracion.html', user=user)

@app.route('/update_config', methods=['POST'])
@login_required # Asegúrate que @login_required esté definido o importado
def update_config():
    current_username = session['username']
    user = users_collection.find_one({'username': current_username})
    if not user:
        flash('Error: Usuario no encontrado.', 'error')
        return redirect(url_for('login'))

    # Determinar qué formulario se envió (si separaste los botones)
    action = request.form.get('action') # Necesitarás añadir name="action" a tus botones submit

    updated_fields = {}
    password_updated = False
    username_changed = False

    # --- Lógica para Actualizar Cuenta (Email y Username) ---
    if action == 'update_account':
        new_email = request.form.get('email', '').strip().lower()
        new_username = request.form.get('username', '').strip() # Obtener nuevo username

        # Validar y actualizar email
        if new_email and new_email != user.get('email'):
            if users_collection.find_one({'email': new_email}):
                flash('El nuevo correo electrónico ya está en uso.', 'error')
                return redirect(url_for('configuracion'))
            updated_fields['email'] = new_email

        # --- Validar y actualizar username ---
        if new_username and new_username != current_username:
            if not new_username: # No permitir username vacío
                 flash('El nombre de usuario no puede estar vacío.', 'error')
                 return redirect(url_for('configuracion'))
            if users_collection.find_one({'username': new_username}):
                flash('El nuevo nombre de usuario ya está en uso.', 'error')
                return redirect(url_for('configuracion'))
            updated_fields['username'] = new_username
            username_changed = True # Marcar que el username cambió

    # --- Lógica para Actualizar Contraseña ---
    elif action == 'update_password':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')

        if password: # Solo si se ingresó una nueva contraseña
            if password != confirm_password:
                flash('Las nuevas contraseñas no coinciden.', 'error')
                return redirect(url_for('configuracion'))
            if len(password) < 6: # Ejemplo: Mínimo 6 caracteres
                 flash('La contraseña debe tener al menos 6 caracteres.', 'error')
                 return redirect(url_for('configuracion'))
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            updated_fields['password'] = hashed_password
            password_updated = True

    # Aplicar actualizaciones a la base de datos si hay cambios
    if updated_fields:
        users_collection.update_one({'username': current_username}, {'$set': updated_fields})
        
        # Si el username cambió, ACTUALIZAR la SESIÓN y otros lugares
        if username_changed:
            new_username_val = updated_fields['username']
            # Actualizar posts del usuario
            posts_collection.update_many({'username': current_username}, {'$set': {'username': new_username_val}})
            # Actualizar comentarios del usuario
            posts_collection.update_many({'comments.username': current_username}, {'$set': {'comments.$[elem].username': new_username_val}}, array_filters=[{'elem.username': current_username}])
            # Actualizar likes del usuario
            posts_collection.update_many({'likes': current_username}, {'$set': {'likes.$': new_username_val}}) # Esto podría necesitar ajuste si un usuario puede likear varias veces (no debería) o $pull/$push
            # Actualizar membresías y creación de comunidades
            comunidades_collection.update_many({'creator': current_username}, {'$set': {'creator': new_username_val}})
            comunidades_collection.update_many({'members': current_username}, {'$set': {'members.$': new_username_val}})
            # Actualizar posts y comentarios DENTRO de comunidades... (similar a posts_collection)
            # ... (Esta parte puede ser compleja, considera si es crucial actualizar nombres retroactivamente en todos lados)

            session['username'] = new_username_val # ¡MUY IMPORTANTE ACTUALIZAR LA SESIÓN!
        
        flash('Configuración actualizada exitosamente.', 'success')
    elif action: # Si se hizo clic en un botón pero no hubo cambios válidos
         flash('No se realizaron cambios.', 'info')

    return redirect(url_for('configuracion'))

@app.route('/update_profile_pic', methods=['POST'])
@login_required
def update_profile_pic():
    file = request.files.get('profile_pic')
    if file and allowed_file(file.filename):
        try:
            profile_pic_data = {
                'data': binary.Binary(file.read()),
                'filename': secure_filename(file.filename),
                'content_type': file.content_type
            }
            users_collection.update_one(
                {'username': session['username']},
                {'$set': {'profile_pic': profile_pic_data}}
            )
            flash('Foto de perfil actualizada exitosamente', 'success')
        except Exception as e:
             flash(f'Error al guardar la imagen: {e}', 'error')
    elif file: # Si se subió un archivo pero no es válido
        flash('Archivo no válido. Usa PNG, JPG, JPEG, WEBP o MP4.', 'error')
    # Si no se subió archivo, no hacer nada o mostrar un mensaje
    # else:
    #    flash('No se seleccionó ningún archivo.', 'info')
    return redirect(url_for('perfil'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    username = session['username']
    
    # Considera añadir una confirmación de contraseña aquí por seguridad

    # Eliminar posts, comentarios del usuario, likes dados?
    posts_collection.delete_many({'username': username})
    # Eliminar usuario de listas de 'likes' y 'comments' en otros posts (más complejo)
    # posts_collection.update_many({}, {'$pull': {'likes': username}})
    # posts_collection.update_many({'comments.username': username}, {'$pull': {'comments': {'username': username}}})

    # Eliminar usuario de comunidades (miembros y creador?)
    # Si es creador, ¿qué pasa con la comunidad? ¿Se elimina? ¿Se transfiere?
    comunidades_collection.update_many({}, {'$pull': {'members': username}})
    # Considerar qué hacer con las comunidades creadas por el usuario

    # Eliminar usuario
    users_collection.delete_one({'username': username})
    
    session.pop('username', None)
    flash('Tu cuenta ha sido eliminada permanentemente', 'success')
    return redirect(url_for('index'))

# --- Rutas de Publicaciones (Posts) ---

@app.route('/post', methods=['POST']) # Cambiado de '/post' a '/create_post' por claridad
@login_required
def create_post():
    text = request.form.get('text', '').strip()
    link = request.form.get('link', '').strip()
    file = request.files.get('media')
    media_data = None

    if not text and not file: # Requiere al menos texto o archivo
         flash('La publicación debe contener texto o un archivo multimedia.', 'error')
         return redirect(url_for('index'))

    if file and allowed_file(file.filename):
        try:
            media_data = {
                'data': binary.Binary(file.read()),
                'filename': secure_filename(file.filename),
                'content_type': file.content_type
            }
        except Exception as e:
            flash(f'Error al procesar el archivo: {e}', 'error')
            return redirect(url_for('index'))
    elif file:
         flash('Tipo de archivo no permitido.', 'error')
         return redirect(url_for('index'))

    post = {
        'username': session['username'],
        'text': text,
        'media_data': media_data, 
        'link': link,
        'timestamp': datetime.utcnow(),
        'likes': [],
        'comments': []
    }
    posts_collection.insert_one(post)
    flash('Publicación creada exitosamente', 'success')
    return redirect(url_for('index'))


@app.route('/edit/<post_id>', methods=['POST'])
@login_required
def edit_post(post_id):
    try:
        post = posts_collection.find_one({'_id': ObjectId(post_id)})
    except Exception as e:
         flash('ID de publicación inválido.', 'error')
         return redirect(url_for('index'))

    if not post:
        flash('Publicación no encontrada', 'error')
        return redirect(url_for('index'))
    if post.get('username') != session['username']:
        flash('No tienes permiso para editar esta publicación', 'error')
        return redirect(url_for('index'))

    text = request.form.get('text', '').strip()
    link = request.form.get('link', '').strip()
    file = request.files.get('media')
    media_data = post.get('media_data') # Mantener la existente por defecto

    if not text and not file and not media_data and not link: # Evitar posts vacíos al editar
         flash('La publicación no puede quedar completamente vacía.', 'error')
         # Podrías redirigir a una página de edición o recargar index
         return redirect(url_for('index')) 

    if file and allowed_file(file.filename):
        try:
            media_data = {
                'data': binary.Binary(file.read()),
                'filename': secure_filename(file.filename),
                'content_type': file.content_type
            }
        except Exception as e:
             flash(f'Error al procesar el archivo: {e}', 'error')
             return redirect(url_for('index'))
    elif file:
         flash('Tipo de archivo no permitido al editar.', 'error')
         return redirect(url_for('index'))

    posts_collection.update_one(
        {'_id': ObjectId(post_id)},
        {'$set': {
            'text': text,
            'link': link,
            'media_data': media_data,
            'timestamp': datetime.utcnow() # Actualizar timestamp al editar? Opcional
        }}
    )
    flash('Publicación actualizada exitosamente', 'success')
    return redirect(url_for('index'))

@app.route('/delete/<post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    try:
        post = posts_collection.find_one({'_id': ObjectId(post_id)})
    except Exception as e:
         flash('ID de publicación inválido.', 'error')
         return redirect(url_for('index'))
         
    if not post:
        flash('Publicación no encontrada', 'error')
        return redirect(url_for('index'))
    if post.get('username') != session['username']:
        flash('No tienes permiso para eliminar esta publicación', 'error')
        return redirect(url_for('index'))

    posts_collection.delete_one({'_id': ObjectId(post_id)})
    flash('Publicación eliminada exitosamente', 'success')
    return redirect(url_for('index'))

@app.route('/like/<post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    username = session['username']
    try:
        # Intenta añadir el like solo si el usuario no está ya en la lista
        result = posts_collection.update_one(
            {'_id': ObjectId(post_id), 'likes': {'$ne': username}},
            {'$push': {'likes': username}}
        )
        # Si no se modificó (porque ya existía), quitar el like (toggle)
        if result.modified_count == 0:
             posts_collection.update_one(
                 {'_id': ObjectId(post_id)},
                 {'$pull': {'likes': username}}
             )
    except Exception as e:
         flash('Error al procesar el like.', 'error')
         print(f"Like error: {e}")
    # Redirigir a la misma página o usar AJAX para mejor UX
    return redirect(request.referrer or url_for('index')) 

@app.route('/comment/<post_id>', methods=['POST'])
@login_required
def comment_post(post_id):
    comment_text = request.form.get('comment', '').strip()
    if not comment_text:
         flash('El comentario no puede estar vacío.', 'error')
         return redirect(request.referrer or url_for('index'))

    comment = {
        # '_id': ObjectId(), # MongoDB añade _id automáticamente a subdocumentos si no se especifica
        'username': session['username'],
        'text': comment_text,
        'timestamp': datetime.utcnow()
    }
    try:
        result = posts_collection.update_one(
            {'_id': ObjectId(post_id)},
            {'$push': {'comments': comment}}
        )
        if result.matched_count == 0:
             flash('Publicación no encontrada.', 'error')
    except Exception as e:
         flash('Error al guardar el comentario.', 'error')
         print(f"Comment error: {e}")

    return redirect(request.referrer or url_for('index'))

@app.route('/edit_comment/<post_id>/<comment_index>', methods=['POST'])
@login_required
def edit_comment(post_id, comment_index):
    try:
        post = posts_collection.find_one({'_id': ObjectId(post_id)})
        comment_index_int = int(comment_index) # Convertir a entero
    except Exception as e:
        flash('ID de publicación o índice de comentario inválido.', 'error')
        return redirect(url_for('index'))

    comments = post.get('comments', [])
    if not post or comment_index_int >= len(comments):
        flash('Comentario no encontrado', 'error')
        return redirect(url_for('index'))

    comment = comments[comment_index_int]
    if comment.get('username') != session['username']:
        flash('Solo puedes editar tus propios comentarios', 'error')
        return redirect(url_for('index'))

    new_text = request.form.get('comment', '').strip()
    if not new_text:
        flash('El comentario no puede quedar vacío.', 'error')
        return redirect(request.referrer or url_for('index'))

    # Actualizar usando la posición del array
    update_field = f'comments.{comment_index_int}.text'
    posts_collection.update_one(
        {'_id': ObjectId(post_id)},
        {'$set': {update_field: new_text}}
    )
    flash('Comentario editado exitosamente', 'success')
    return redirect(request.referrer or url_for('index'))

# --- Rutas de Comunidades (Guilds) ---
# (Tu código de comunidades se ve bastante bien, solo añado @login_required y mejoras menores)

@app.route('/create_community', methods=['POST'])
@login_required
def create_community():
    name = request.form.get('name', '').strip()
    tags_str = request.form.get('tags', '')
    file = request.files.get('banner')
    banner_data = None

    if not name:
        flash('El nombre de la comunidad es requerido.', 'error')
        return redirect(request.referrer or url_for('index'))

    if file and allowed_file(file.filename):
        try:
            banner_data = {
                'data': binary.Binary(file.read()),
                'filename': secure_filename(file.filename),
                'content_type': file.content_type
            }
        except Exception as e:
             flash(f'Error al procesar el banner: {e}', 'error')
             return redirect(request.referrer or url_for('index'))
    elif file:
        flash('Tipo de archivo no permitido para el banner.', 'error')
        return redirect(request.referrer or url_for('index'))

    # Limpiar y procesar tags
    tags = [tag.strip() for tag in tags_str.split(',') if tag.strip()] 

    community = {
        'name': name,
        'creator': session['username'],
        'banner_data': banner_data,
        'tags': tags, 
        'created_at': datetime.utcnow(),
        'members': [session['username']], 
        'posts': [] 
    }
    try:
        result = comunidades_collection.insert_one(community)
        flash('Guild creado exitosamente', 'success') # Cambiado a Guild
        return redirect(url_for('community', community_id=str(result.inserted_id)))
    except Exception as e: # Captura posible error de duplicado si tienes índices únicos
        flash(f'Error al crear el Guild: {e}', 'error')
        return redirect(url_for('index'))


@app.route('/community/<community_id>')
def community(community_id):
    try:
        community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
    except Exception as e:
         flash('ID de Guild inválido.', 'error')
         return redirect(url_for('index'))
         
    if not community:
        flash('Guild no encontrado', 'error') # Cambiado a Guild
        return redirect(url_for('index'))

    community['_id'] = str(community['_id'])
    # Asegurar que posts y members existan
    posts = community.get('posts', [])
    members = community.get('members', [])
    
    # Convertir _id de posts a string (si existen)
    for post in posts:
        post['_id'] = str(post.get('_id', ObjectId())) # Usar get con default
        post['comments'] = post.get('comments', [])
        post['likes'] = post.get('likes', [])

    is_member = 'username' in session and session['username'] in members
    is_creator = 'username' in session and session['username'] == community.get('creator')
    
    # Pasar posts ordenados por fecha a la plantilla
    posts_sorted = sorted(posts, key=lambda p: p.get('timestamp', datetime.min), reverse=True)

    return render_template('comunidad.html', 
                           community=community, 
                           posts=posts_sorted, 
                           is_member=is_member, 
                           is_creator=is_creator)

# Ruta para EDITAR los detalles de la comunidad (Nombre, Tags)
@app.route('/edit_community/<community_id>', methods=['POST'])
@login_required 
def edit_community(community_id):
    try:
        community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
        if not community:
            flash('Guild no encontrado.', 'error')
            return redirect(url_for('index'))
        
        # Solo el creador puede editar
        if session['username'] != community.get('creator'):
             flash('No tienes permiso para editar este Guild.', 'error')
             return redirect(url_for('community', community_id=community_id))

        new_name = request.form.get('name', '').strip()
        tags_str = request.form.get('tags', '')
        
        if not new_name:
             flash('El nombre del Guild no puede estar vacío.', 'error')
             return redirect(url_for('community', community_id=community_id))

        # Validar si el nuevo nombre ya existe (opcional)
        if new_name != community.get('name') and comunidades_collection.find_one({'name': new_name}):
             flash('Ya existe un Guild con ese nombre.', 'error')
             return redirect(url_for('community', community_id=community_id))

        new_tags = [tag.strip() for tag in tags_str.split(',') if tag.strip()]

        comunidades_collection.update_one(
            {'_id': ObjectId(community_id)},
            {'$set': {
                'name': new_name,
                'tags': new_tags
            }}
        )
        flash('Información del Guild actualizada.', 'success')

    except Exception as e:
        flash(f'Error al editar el Guild: {e}', 'error')
        print(f"Edit community error: {e}")

    return redirect(url_for('community', community_id=community_id))

# Ruta para ELIMINAR una comunidad
@app.route('/delete_community/<community_id>', methods=['POST'])
@login_required
def delete_community(community_id):
    try:
        community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
        if not community:
            flash('Guild no encontrado.', 'error')
            return redirect(url_for('index'))
        
        # Solo el creador puede eliminar
        if session['username'] != community.get('creator'):
             flash('No tienes permiso para eliminar este Guild.', 'error')
             return redirect(url_for('community', community_id=community_id))

        # ¡Eliminación!
        comunidades_collection.delete_one({'_id': ObjectId(community_id)})
        
        flash(f'Guild "{community.get("name")}" eliminado permanentemente.', 'success')
        return redirect(url_for('index')) # Redirigir al inicio después de eliminar

    except Exception as e:
        flash(f'Error al eliminar el Guild: {e}', 'error')
        print(f"Delete community error: {e}")
        return redirect(url_for('community', community_id=community_id)) 

# Ruta para EDITAR un comentario DENTRO de una comunidad
@app.route('/edit_community_comment/<community_id>/<post_id>/<comment_index>', methods=['POST'])
@login_required 
def edit_community_comment(community_id, post_id, comment_index):
    try:
        community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
        comment_index_int = int(comment_index)
        
        if not community:
            flash('Guild no encontrado.', 'error')
            return redirect(url_for('index'))

        # Encontrar el post y el comentario específico
        post_obj_id = ObjectId(post_id)
        post_index = -1
        target_comment = None
        comments = []
        for i, p in enumerate(community.get('posts', [])):
             if p.get('_id') == post_obj_id:
                  post_index = i
                  comments = p.get('comments', [])
                  if 0 <= comment_index_int < len(comments):
                       target_comment = comments[comment_index_int]
                  break 
        
        if post_index == -1 or target_comment is None:
            flash('Publicación o comentario no encontrado.', 'error')
            return redirect(url_for('community', community_id=community_id))

        if target_comment.get('username') != session['username']:
            flash('Solo puedes editar tus propios comentarios.', 'error')
            return redirect(url_for('community', community_id=community_id))

        new_text = request.form.get('comment', '').strip()
        if not new_text:
            flash('El comentario no puede quedar vacío.', 'error')
            return redirect(url_for('community', community_id=community_id))

        update_field = f'posts.{post_index}.comments.{comment_index_int}.text'
        comunidades_collection.update_one(
            {'_id': ObjectId(community_id)},
            {'$set': {update_field: new_text}}
        )
        flash('Comentario editado exitosamente.', 'success')

    except Exception as e:
        flash(f'Error al editar el comentario: {e}', 'error')
        print(f"Edit community comment error: {e}")

    return redirect(url_for('community', community_id=community_id))

@app.route('/delete_community_post/<community_id>/<post_id>', methods=['POST'])
@login_required
def delete_community_post(community_id, post_id):
    # (Tu lógica es correcta, solo añadir manejo de errores y mensajes consistentes)
    try:
        community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
        if not community:
            flash('Guild no encontrado', 'error')
            return redirect(url_for('index'))

        # Encuentra el post usando ObjectId
        post_obj_id = ObjectId(post_id)
        post = next((p for p in community.get('posts', []) if p.get('_id') == post_obj_id), None)

        if not post:
             flash('Publicación no encontrada en este Guild.', 'error')
             return redirect(url_for('community', community_id=community_id))

        if session['username'] != community.get('creator') and session['username'] != post.get('username'):
            flash('No tienes permiso para eliminar esta publicación', 'error')
            return redirect(url_for('community', community_id=community_id))

        comunidades_collection.update_one(
            {'_id': ObjectId(community_id)},
            {'$pull': {'posts': {'_id': post_obj_id}}}
        )
        flash('Publicación eliminada exitosamente', 'success')
    except Exception as e:
        flash(f'Error al eliminar la publicación: {e}', 'error')
        print(f"Delete comm post error: {e}")
        
    return redirect(url_for('community', community_id=community_id))


@app.route('/edit_community_post/<community_id>/<post_id>', methods=['POST'])
@login_required
def edit_community_post(community_id, post_id):
     # (Tu lógica es mayormente correcta, añadir validaciones)
    try:
        community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
        if not community:
            flash('Guild no encontrado', 'error')
            return redirect(url_for('index'))

        post_obj_id = ObjectId(post_id)
        post_index = -1
        original_post = None
        for i, p in enumerate(community.get('posts', [])):
            if p.get('_id') == post_obj_id:
                post_index = i
                original_post = p
                break
        
        if post_index == -1 or not original_post:
             flash('Publicación no encontrada en este Guild.', 'error')
             return redirect(url_for('community', community_id=community_id))

        if session['username'] != original_post.get('username'):
            flash('Solo el autor puede editar esta publicación', 'error')
            return redirect(url_for('community', community_id=community_id))

        text = request.form.get('text', '').strip()
        link = request.form.get('link', '').strip()
        file = request.files.get('media')
        media_data = original_post.get('media_data') # Mantener la existente

        if not text and not file and not media_data and not link:
            flash('La publicación no puede quedar completamente vacía.', 'error')
            return redirect(url_for('community', community_id=community_id))

        if file and allowed_file(file.filename):
            try:
                media_data = {
                    'data': binary.Binary(file.read()),
                    'filename': secure_filename(file.filename),
                    'content_type': file.content_type
                }
            except Exception as e:
                 flash(f'Error al procesar el archivo: {e}', 'error')
                 return redirect(url_for('community', community_id=community_id))
        elif file:
             flash('Tipo de archivo no permitido al editar.', 'error')
             return redirect(url_for('community', community_id=community_id))

        # Actualizar usando la posición del array
        update_prefix = f'posts.{post_index}.'
        comunidades_collection.update_one(
            {'_id': ObjectId(community_id)},
            {'$set': {
                update_prefix + 'text': text,
                update_prefix + 'link': link,
                update_prefix + 'media_data': media_data,
                update_prefix + 'timestamp': datetime.utcnow() # Opcional: actualizar timestamp
            }}
        )
        flash('Publicación editada exitosamente', 'success')

    except Exception as e:
        flash(f'Error al editar la publicación: {e}', 'error')
        print(f"Edit comm post error: {e}")

    return redirect(url_for('community', community_id=community_id))


@app.route('/delete_community_comment/<community_id>/<post_id>/<comment_index>', methods=['POST'])
@login_required
def delete_community_comment(community_id, post_id, comment_index):
    # (Tu lógica de unset/pull es correcta para eliminar por índice)
    try:
        community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
        comment_index_int = int(comment_index)

        if not community:
             flash('Guild no encontrado', 'error')
             return redirect(url_for('index'))
        if session['username'] != community.get('creator'): # Solo el creador puede eliminar
            flash('Solo el creador del Guild puede eliminar comentarios', 'error')
            return redirect(url_for('community', community_id=community_id))
        
        # Verificar que el post y el comentario existan en el índice
        post_obj_id = ObjectId(post_id)
        post_index = -1
        comments = []
        for i, p in enumerate(community.get('posts', [])):
             if p.get('_id') == post_obj_id:
                  post_index = i
                  comments = p.get('comments', [])
                  break
        
        if post_index == -1 or comment_index_int >= len(comments):
             flash('Publicación o comentario no encontrado.', 'error')
             return redirect(url_for('community', community_id=community_id))

        # Eliminar por índice
        update_field = f'posts.{post_index}.comments.{comment_index_int}'
        comunidades_collection.update_one(
            {'_id': ObjectId(community_id)},
            {'$unset': {update_field: ""}}
        )
        # Limpiar el null resultante
        pull_field = f'posts.{post_index}.comments'
        comunidades_collection.update_one(
            {'_id': ObjectId(community_id)},
            {'$pull': {pull_field: None}}
        )
        flash('Comentario eliminado exitosamente', 'success')
    except Exception as e:
        flash(f'Error al eliminar el comentario: {e}', 'error')
        print(f"Delete comm comment error: {e}")

    return redirect(url_for('community', community_id=community_id))



# Ruta para SALIR de una comunidad
@app.route('/leave_community/<community_id>', methods=['POST'])
@login_required
def leave_community(community_id):
    username = session['username']
    try:
        community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
        if not community:
            flash('Guild no encontrado', 'error')
            return redirect(url_for('index'))
        
        # No permitir al creador salir (debería eliminar el guild?)
        if username == community.get('creator'):
            flash('El creador no puede salir del Guild. Puedes eliminarlo si lo deseas.', 'error')
            return redirect(url_for('community', community_id=community_id))

        result = comunidades_collection.update_one(
            {'_id': ObjectId(community_id)},
            {'$pull': {'members': username}}
        )
        if result.modified_count > 0:
            flash('Has salido del Guild.', 'success')
        else:
            flash('No eras miembro de este Guild.', 'info')
            
    except Exception as e:
         flash(f'Error al salir del Guild: {e}', 'error')
         print(f"Leave community error: {e}")
         
    # Redirigir a la página de la comunidad o al index
    return redirect(url_for('community', community_id=community_id)) 


# Ruta para ACTUALIZAR el banner de la comunidad
@app.route('/update_community_banner/<community_id>', methods=['POST'])
@login_required
def update_community_banner(community_id):
    try:
        community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
        if not community:
            flash('Guild no encontrado', 'error')
            return redirect(url_for('index'))
        
        # Solo el creador puede cambiar el banner
        if session['username'] != community.get('creator'):
             flash('Solo el creador puede cambiar el banner.', 'error')
             return redirect(url_for('community', community_id=community_id))

        file = request.files.get('community_banner')
        if file and allowed_file(file.filename):
            try:
                banner_data = {
                    'data': binary.Binary(file.read()),
                    'filename': secure_filename(file.filename),
                    'content_type': file.content_type
                }
                comunidades_collection.update_one(
                    {'_id': ObjectId(community_id)},
                    {'$set': {'banner_data': banner_data}}
                )
                flash('Banner del Guild actualizado exitosamente', 'success')
            except Exception as e:
                 flash(f'Error al guardar el banner: {e}', 'error')
        elif file: 
            flash('Archivo no válido para el banner.', 'error')
            
    except Exception as e:
         flash(f'Error al actualizar el banner: {e}', 'error')
         print(f"Update community banner error: {e}")

    return redirect(url_for('community', community_id=community_id))

@app.route('/remove_community_member/<community_id>/<username>', methods=['POST'])
@login_required
def remove_community_member(community_id, username):
    # (Tu lógica es correcta)
    try:
        community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
        if not community:
            flash('Guild no encontrado', 'error')
            return redirect(url_for('index'))
        if session['username'] != community.get('creator'):
            flash('Solo el creador puede eliminar miembros', 'error')
            return redirect(url_for('community', community_id=community_id))
        if username == community.get('creator'):
            flash('No puedes eliminar al creador del Guild', 'error')
            return redirect(url_for('community', community_id=community_id))

        result = comunidades_collection.update_one(
            {'_id': ObjectId(community_id)},
            {'$pull': {'members': username}}
        )
        if result.modified_count > 0:
            flash(f'{username} ha sido eliminado del Guild', 'success')
        else:
             flash(f'{username} no es miembro de este Guild.', 'info')

    except Exception as e:
        flash(f'Error al eliminar miembro: {e}', 'error')
        print(f"Remove member error: {e}")

    return redirect(url_for('community', community_id=community_id))


@app.route('/join_community/<community_id>', methods=['POST'])
@login_required
def join_community(community_id):
    # (Tu lógica es correcta)
    username = session['username']
    try:
        community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
        if not community:
            flash('Guild no encontrado', 'error')
            return redirect(url_for('index'))

        if username not in community.get('members', []):
            comunidades_collection.update_one(
                {'_id': ObjectId(community_id)},
                {'$push': {'members': username}}
            )
            flash('Te has unido al Guild exitosamente', 'success')
        else:
            flash('Ya eres miembro de este Guild', 'info')
    except Exception as e:
         flash(f'Error al unirse al Guild: {e}', 'error')
         print(f"Join community error: {e}")
         
    return redirect(url_for('community', community_id=community_id))


@app.route('/community_post/<community_id>', methods=['POST']) # Crear post EN comunidad
@login_required
def create_community_post(community_id):
     # (Tu lógica es correcta, añadir validaciones)
    try:
        community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
        if not community:
             flash('Guild no encontrado.', 'error')
             return redirect(url_for('index'))
        if session['username'] not in community.get('members', []):
            flash('Debes ser miembro del Guild para publicar', 'error')
            return redirect(url_for('community', community_id=community_id))

        text = request.form.get('text', '').strip()
        link = request.form.get('link', '').strip()
        file = request.files.get('media')
        media_data = None

        if not text and not file:
            flash('La publicación debe contener texto o un archivo multimedia.', 'error')
            return redirect(url_for('community', community_id=community_id))

        if file and allowed_file(file.filename):
            try:
                media_data = {
                    'data': binary.Binary(file.read()),
                    'filename': secure_filename(file.filename),
                    'content_type': file.content_type
                }
            except Exception as e:
                 flash(f'Error al procesar el archivo: {e}', 'error')
                 return redirect(url_for('community', community_id=community_id))
        elif file:
             flash('Tipo de archivo no permitido.', 'error')
             return redirect(url_for('community', community_id=community_id))

        post = {
            '_id': ObjectId(), # Generar ObjectId aquí
            'username': session['username'],
            'text': text,
            'media_data': media_data,
            'link': link,
            'timestamp': datetime.utcnow(),
            'likes': [],
            'comments': []
        }
        comunidades_collection.update_one(
            {'_id': ObjectId(community_id)},
            {'$push': {'posts': post}}
        )
        flash('Publicación creada exitosamente en el Guild', 'success')

    except Exception as e:
        flash(f'Error al crear la publicación: {e}', 'error')
        print(f"Create comm post error: {e}")

    return redirect(url_for('community', community_id=community_id))


@app.route('/community_like/<community_id>/<post_id>', methods=['POST'])
@login_required
def like_community_post(community_id, post_id):
    # (Aplicar lógica de toggle like)
    username = session['username']
    try:
        post_obj_id = ObjectId(post_id)
        # Intenta añadir si no existe
        result = comunidades_collection.update_one(
            {'_id': ObjectId(community_id), 'posts._id': post_obj_id, 'posts.likes': {'$ne': username}},
            {'$push': {'posts.$.likes': username}}
        )
        # Si no se modificó (ya existía), quitar
        if result.modified_count == 0:
            comunidades_collection.update_one(
                {'_id': ObjectId(community_id), 'posts._id': post_obj_id},
                {'$pull': {'posts.$.likes': username}}
            )
    except Exception as e:
        flash('Error al procesar el like.', 'error')
        print(f"Like comm post error: {e}")
        
    return redirect(request.referrer or url_for('community', community_id=community_id))


@app.route('/community_comment/<community_id>/<post_id>', methods=['POST'])
@login_required
def comment_community_post(community_id, post_id):
     # (Tu lógica es correcta, añadir validaciones)
    comment_text = request.form.get('comment', '').strip()
    if not comment_text:
         flash('El comentario no puede estar vacío.', 'error')
         return redirect(request.referrer or url_for('community', community_id=community_id))
         
    comment = {
        'username': session['username'],
        'text': comment_text,
        'timestamp': datetime.utcnow()
    }
    try:
        result = comunidades_collection.update_one(
            {'_id': ObjectId(community_id), 'posts._id': ObjectId(post_id)},
            {'$push': {'posts.$.comments': comment}}
        )
        if result.matched_count == 0:
             flash('Publicación o Guild no encontrado.', 'error')
    except Exception as e:
         flash('Error al guardar el comentario.', 'error')
         print(f"Comment comm post error: {e}")

    return redirect(request.referrer or url_for('community', community_id=community_id))

# 1. Ruta para SERVIR el banner del perfil
@app.route('/profile_banner/<username>')
def serve_profile_banner(username):
    try:
        user = users_collection.find_one({'username': username})
        # ASUME que guardarás los datos del banner en un campo llamado 'profile_banner'
        if user and 'profile_banner' in user and user['profile_banner']: 
            banner = user['profile_banner']
            return send_file(
                io.BytesIO(banner['data']),
                mimetype=banner['content_type'],
                as_attachment=False,
                download_name=banner['filename']
            )
        else:
            # Si no hay banner personalizado, sirve uno por defecto
            # Asegúrate de tener 'default-banner.jpg' en 'static/img/'
             try:
                 return send_file('static/img/default-banner.jpg', mimetype='image/jpeg')
             except FileNotFoundError:
                 print("Error: Default banner 'static/img/default-banner.jpg' not found.")
                 return "Banner predeterminado no encontrado", 404
                 
    except Exception as e:
        print(f"Error serving profile banner for user {username}: {e}")
        # En caso de error, también sirve el predeterminado
        try:
            return send_file('static/img/default-banner.jpg', mimetype='image/jpeg')
        except FileNotFoundError:
             print("Error: Default banner 'static/img/default-banner.jpg' not found.")
             return "Banner predeterminado no encontrado", 404

# 2. Ruta para ACTUALIZAR el banner del perfil
@app.route('/update_profile_banner', methods=['POST'])
@login_required # Asegúrate de tener este decorador definido
def update_profile_banner():
    file = request.files.get('banner_pic')
    if file and allowed_file(file.filename): # Reutiliza tu función allowed_file
        try:
            banner_pic_data = {
                'data': binary.Binary(file.read()),
                'filename': secure_filename(file.filename),
                'content_type': file.content_type
            }
            # Guarda los datos en el campo 'profile_banner' del usuario
            users_collection.update_one(
                {'username': session['username']},
                {'$set': {'profile_banner': banner_pic_data}}
            )
            flash('Banner de perfil actualizado exitosamente', 'success')
        except Exception as e:
             flash(f'Error al guardar el banner: {e}', 'error')
    elif file: 
        flash('Archivo no válido para el banner.', 'error')
    
    return redirect(url_for('perfil')) # Redirige de vuelta al perfil


# --- Ejecución de la App ---
if __name__ == '__main__':
    # Considera usar Gunicorn o Waitress para producción en lugar de app.run(debug=True)
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))