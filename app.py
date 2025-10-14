from flask import Flask, render_template, request, redirect, url_for, session, flash,send_file
from pymongo import MongoClient
import bcrypt
from werkzeug.utils import secure_filename
from bson import ObjectId,binary
import os
import io
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_aqui'

# Configuración de MongoDB Atlas
client = MongoClient('mongodb+srv://zaida:5bvTAAUKVWkOCUbd@cluster0.4r084.mongodb.net/')
db = client['nekopixel']
users_collection = db['usuarios']
posts_collection = db['publicaciones']
comunidades_collection = db['comunidades']

#guardar archivos subidos
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'mp4'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Ruta para servir archivos multimedia desde MongoDB
@app.route('/media/<post_id>')
def serve_media(post_id):
    post = posts_collection.find_one({'_id': ObjectId(post_id)})
    if post and 'media_data' in post:
        return send_file(
            io.BytesIO(post['media_data']['data']),
            mimetype=post['media_data']['content_type'],
            as_attachment=False,
            download_name=post['media_data']['filename']
        )
    return "Archivo no encontrado", 404

# Ruta para servir archivos multimedia de publicaciones dentro de una comunidad
@app.route('/community_media/<community_id>/<post_id>')
def serve_community_media(community_id, post_id):
    community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
    if not community:
        return "Comunidad no encontrada", 404

    # Buscar la publicación dentro del array 'posts'
    for post in community.get('posts', []):
        if str(post['_id']) == post_id and 'media_data' in post:
            return send_file(
                io.BytesIO(post['media_data']['data']),
                mimetype=post['media_data']['content_type'],
                as_attachment=False,
                download_name=post['media_data']['filename']
            )
    return "Archivo no encontrado", 404

# Ruta para servir la imagen de la comunidad desde MongoDB
@app.route('/community_banner/<community_id>')
def serve_community_banner(community_id):
    community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
    if community and 'banner_data' in community:
        return send_file(
            io.BytesIO(community['banner_data']['data']),
            mimetype=community['banner_data']['content_type'],
            as_attachment=False,
            download_name=community['banner_data']['filename']
        )
    return "Imagen no encontrada", 404


# Ruta de inicio con publicaciones y comunidades recomendadas
@app.route('/')
def index():
    posts = list(posts_collection.find().sort("timestamp", -1))
    for post in posts:
        post['_id'] = str(post['_id'])
    
    # Obtener todas las comunidades
    communities = list(comunidades_collection.find())
    for community in communities:
        community['_id'] = str(community['_id'])
    
    return render_template('index.html', posts=posts, communities=communities)

# Ruta para crear una comunidad
@app.route('/create_community', methods=['POST'])
def create_community():
    if 'username' not in session:
        flash('Debes iniciar sesión para crear una comunidad', 'error')
        return redirect(url_for('index'))

    name = request.form.get('name')
    tags = request.form.get('tags').split(',')  # Convertir las etiquetas en lista
    file = request.files.get('banner')

    banner_data = None
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        content_type = file.content_type
        banner_data = {
            'data': binary.Binary(file.read()),
            'filename': filename,
            'content_type': content_type
        }

    community = {
        'name': name,
        'creator': session['username'],
        'banner_data': banner_data,
        'tags': [tag.strip() for tag in tags if tag.strip()],  # Limpiar etiquetas vacías
        'created_at': datetime.utcnow(),
        'members': [session['username']],  # El creador es el primer miembro
        'posts': []  # Lista de publicaciones (inicialmente vacía)
    }
    result = comunidades_collection.insert_one(community)
    flash('Comunidad creada exitosamente', 'success')
    return redirect(url_for('community', community_id=str(result.inserted_id)))

# Ruta para ver una comunidad específica
@app.route('/community/<community_id>')
def community(community_id):
    community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
    if not community:
        flash('Comunidad no encontrada', 'error')
        return redirect(url_for('index'))

    community['_id'] = str(community['_id'])
    posts = community.get('posts', [])
    for post in posts:
        post['_id'] = str(post.get('_id', ObjectId()))

    is_member = 'username' in session and session['username'] in community.get('members', [])
    is_creator = 'username' in session and session['username'] == community['creator']
    return render_template('comunidad.html', community=community, posts=posts, is_member=is_member, is_creator=is_creator)

# Ruta para eliminar una publicación (creador o autor)
@app.route('/delete_community_post/<community_id>/<post_id>', methods=['POST'])
def delete_community_post(community_id, post_id):
    if 'username' not in session:
        flash('Debes iniciar sesión para realizar esta acción', 'error')
        return redirect(url_for('community', community_id=community_id))

    community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
    if not community:
        flash('Comunidad no encontrada', 'error')
        return redirect(url_for('community', community_id=community_id))

    post = next((p for p in community['posts'] if str(p['_id']) == post_id), None)
    if not post or (session['username'] != community['creator'] and session['username'] != post['username']):
        flash('Solo el creador o el autor puede eliminar esta publicación', 'error')
        return redirect(url_for('community', community_id=community_id))

    comunidades_collection.update_one(
        {'_id': ObjectId(community_id)},
        {'$pull': {'posts': {'_id': ObjectId(post_id)}}}
    )
    flash('Publicación eliminada exitosamente', 'success')
    return redirect(url_for('community', community_id=community_id))

# Ruta para editar una publicación desde el popup (solo autor)
@app.route('/edit_community_post/<community_id>/<post_id>', methods=['POST'])
def edit_community_post(community_id, post_id):
    if 'username' not in session:
        flash('Debes iniciar sesión para realizar esta acción', 'error')
        return redirect(url_for('community', community_id=community_id))

    community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
    if not community:
        flash('Comunidad no encontrada', 'error')
        return redirect(url_for('community', community_id=community_id))

    post = next((p for p in community['posts'] if str(p['_id']) == post_id), None)
    if not post or session['username'] != post['username']:
        flash('Solo el autor puede editar esta publicación', 'error')
        return redirect(url_for('community', community_id=community_id))

    text = request.form.get('text')
    link = request.form.get('link')
    file = request.files.get('media')

    media_data = post['media_data']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        content_type = file.content_type
        media_data = {
            'data': binary.Binary(file.read()),
            'filename': filename,
            'content_type': content_type
        }

    comunidades_collection.update_one(
        {'_id': ObjectId(community_id), 'posts._id': ObjectId(post_id)},
        {'$set': {
            'posts.$.text': text,
            'posts.$.link': link,
            'posts.$.media_data': media_data
        }}
    )
    flash('Publicación editada exitosamente', 'success')
    return redirect(url_for('community', community_id=community_id))

# Ruta para eliminar un comentario
@app.route('/delete_community_comment/<community_id>/<post_id>/<comment_index>', methods=['POST'])
def delete_community_comment(community_id, post_id, comment_index):
    if 'username' not in session:
        flash('Debes iniciar sesión para realizar esta acción', 'error')
        return redirect(url_for('community', community_id=community_id))

    community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
    if not community or session['username'] != community['creator']:
        flash('Solo el creador puede eliminar comentarios', 'error')
        return redirect(url_for('community', community_id=community_id))

    # Usamos el índice para eliminar el comentario específico
    comunidades_collection.update_one(
        {'_id': ObjectId(community_id), 'posts._id': ObjectId(post_id)},
        {'$unset': {f'posts.$.comments.{comment_index}': ""}}
    )
    comunidades_collection.update_one(
        {'_id': ObjectId(community_id), 'posts._id': ObjectId(post_id)},
        {'$pull': {'posts.$.comments': None}}
    )
    flash('Comentario eliminado exitosamente', 'success')
    return redirect(url_for('community', community_id=community_id))

# Ruta para eliminar un usuario de la comunidad
@app.route('/remove_community_member/<community_id>/<username>', methods=['POST'])
def remove_community_member(community_id, username):
    if 'username' not in session:
        flash('Debes iniciar sesión para realizar esta acción', 'error')
        return redirect(url_for('community', community_id=community_id))

    community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
    if not community or session['username'] != community['creator']:
        flash('Solo el creador puede eliminar miembros', 'error')
        return redirect(url_for('community', community_id=community_id))

    if username == community['creator']:
        flash('No puedes eliminarte a ti mismo como creador', 'error')
        return redirect(url_for('community', community_id=community_id))

    comunidades_collection.update_one(
        {'_id': ObjectId(community_id)},
        {'$pull': {'members': username}}
    )
    flash(f'{username} ha sido eliminado de la comunidad', 'success')
    return redirect(url_for('community', community_id=community_id))

# Ruta para unirse a una comunidad
@app.route('/join_community/<community_id>', methods=['POST'])
def join_community(community_id):
    if 'username' not in session:
        flash('Debes iniciar sesión para unirte a una comunidad', 'error')
        return redirect(url_for('login'))

    username = session['username']
    community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
    if not community:
        flash('Comunidad no encontrada', 'error')
        return redirect(url_for('index'))

    if username not in community.get('members', []):
        comunidades_collection.update_one(
            {'_id': ObjectId(community_id)},
            {'$push': {'members': username}}
        )
        flash('Te has unido a la comunidad exitosamente', 'success')
    else:
        flash('Ya eres miembro de esta comunidad', 'info')
    return redirect(url_for('community', community_id=community_id))

# Ruta para crear una publicación en una comunidad (restringida a miembros)
@app.route('/community_post/<community_id>', methods=['POST'])
def create_community_post(community_id):
    if 'username' not in session:
        flash('Debes iniciar sesión para publicar', 'error')
        return redirect(url_for('community', community_id=community_id))

    community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
    if not community or session['username'] not in community.get('members', []):
        flash('Debes ser miembro de la comunidad para publicar', 'error')
        return redirect(url_for('community', community_id=community_id))

    text = request.form.get('text')
    link = request.form.get('link')
    file = request.files.get('media')

    media_data = None
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        content_type = file.content_type
        media_data = {
            'data': binary.Binary(file.read()),
            'filename': filename,
            'content_type': content_type
        }

    post = {
        '_id': ObjectId(),
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
    flash('Publicación creada exitosamente', 'success')
    return redirect(url_for('community', community_id=community_id))

# Ruta para dar like a una publicación en una comunidad
@app.route('/community_like/<community_id>/<post_id>', methods=['POST'])
def like_community_post(community_id, post_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    community = comunidades_collection.find_one({'_id': ObjectId(community_id)})
    if community:
        for post in community.get('posts', []):
            if str(post['_id']) == post_id and session['username'] not in post.get('likes', []):
                comunidades_collection.update_one(
                    {'_id': ObjectId(community_id), 'posts._id': ObjectId(post_id)},
                    {'$push': {'posts.$.likes': session['username']}}
                )
                break
    return redirect(url_for('community', community_id=community_id))

# Ruta para comentar en una publicación en una comunidad
@app.route('/community_comment/<community_id>/<post_id>', methods=['POST'])
def comment_community_post(community_id, post_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    comment_text = request.form.get('comment')
    comment = {
        'username': session['username'],
        'text': comment_text,
        'timestamp': datetime.utcnow()
    }
    comunidades_collection.update_one(
        {'_id': ObjectId(community_id), 'posts._id': ObjectId(post_id)},
        {'$push': {'posts.$.comments': comment}}
    )
    return redirect(url_for('community', community_id=community_id))

# Ruta para crear publicación
@app.route('/post', methods=['POST'])
def create_post():
    if 'username' not in session:
        flash('Debes iniciar sesión para publicar', 'error')
        return redirect(url_for('login'))

    text = request.form.get('text')
    link = request.form.get('link')
    file = request.files.get('media')

    media_data = None
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        content_type = file.content_type  # Obtener el tipo MIME del archivo
        media_data = {
            'data': binary.Binary(file.read()),  # Convertir el archivo a binario
            'filename': filename,
            'content_type': content_type
        }

    post = {
        'username': session['username'],
        'text': text,
        'media_data': media_data,  # Guardar los datos binarios en lugar de una ruta
        'link': link,
        'timestamp': datetime.utcnow(),
        'likes': [],
        'comments': []
    }
    posts_collection.insert_one(post)
    flash('Publicación creada exitosamente', 'success')
    return redirect(url_for('index'))

# Ruta para editar una publicación
@app.route('/edit/<post_id>', methods=['POST'])
def edit_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    post = posts_collection.find_one({'_id': ObjectId(post_id)})
    if not post:
        flash('Publicación no encontrada', 'error')
        return redirect(url_for('index'))
    
    if post['username'] != session['username']:
        flash('No tienes permiso para editar esta publicación', 'error')
        return redirect(url_for('index'))

    text = request.form.get('text')
    link = request.form.get('link')
    file = request.files.get('media')

    media_data = post.get('media_data')  # Mantener los datos existentes por defecto
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        content_type = file.content_type
        media_data = {
            'data': binary.Binary(file.read()),
            'filename': filename,
            'content_type': content_type
        }

    posts_collection.update_one(
        {'_id': ObjectId(post_id)},
        {'$set': {
            'text': text,
            'link': link,
            'media_data': media_data,
            'timestamp': datetime.utcnow()
        }}
    )
    flash('Publicación actualizada exitosamente', 'success')
    return redirect(url_for('index'))

# Ruta para eliminar una publicación
@app.route('/delete/<post_id>', methods=['POST'])
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    post = posts_collection.find_one({'_id': ObjectId(post_id)})
    if not post:
        flash('Publicación no encontrada', 'error')
        return redirect(url_for('index'))
    
    if post['username'] != session['username']:
        flash('No tienes permiso para eliminar esta publicación', 'error')
        return redirect(url_for('index'))

    posts_collection.delete_one({'_id': ObjectId(post_id)})
    flash('Publicación eliminada exitosamente', 'success')
    return redirect(url_for('index'))

# Ruta para dar like
@app.route('/like/<post_id>', methods=['POST'])
def like_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    post = posts_collection.find_one({'_id': ObjectId(post_id)})
    if post and session['username'] not in post.get('likes', []):
        posts_collection.update_one(
            {'_id': ObjectId(post_id)},
            {'$push': {'likes': session['username']}}
        )
    return redirect(url_for('index'))

# Ruta para comentar
@app.route('/comment/<post_id>', methods=['POST'])
def comment_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    comment_text = request.form.get('comment')
    print(f"Comentario recibido: {comment_text} para post_id: {post_id}")  # Depuración
    comment = {
        'username': session['username'],
        'text': comment_text,
        'timestamp': datetime.utcnow()
    }
    result = posts_collection.update_one(
        {'_id': ObjectId(post_id)},
        {'$push': {'comments': comment}}
    )
    print(f"Resultado de la actualización: {result.modified_count} documentos modificados")  # Depuración
    return redirect(url_for('index'))

@app.route('/edit_comment/<post_id>/<comment_index>', methods=['POST'])
def edit_comment(post_id, comment_index):
    if 'username' not in session:
        flash('Debes iniciar sesión para realizar esta acción', 'error')
        return redirect(url_for('index'))

    post = posts_collection.find_one({'_id': ObjectId(post_id)})
    if not post or int(comment_index) >= len(post.get('comments', [])):
        flash('Comentario no encontrado', 'error')
        return redirect(url_for('index'))

    comment = post['comments'][int(comment_index)]
    if comment['username'] != session['username']:
        flash('Solo puedes editar tus propios comentarios', 'error')
        return redirect(url_for('index'))

    new_text = request.form.get('comment')
    posts_collection.update_one(
        {'_id': ObjectId(post_id)},
        {'$set': {f'comments.{comment_index}.text': new_text}}
    )
    flash('Comentario editado exitosamente', 'success')
    return redirect(url_for('index'))

# Ruta de registro (agregar created_at)
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'error')
            return redirect(url_for('registro'))

        if users_collection.find_one({'username': username}):
            flash('El nombre de usuario ya está en uso', 'error')
            return redirect(url_for('registro'))

        if users_collection.find_one({'email': email}):
            flash('El correo electrónico ya está en uso', 'error')
            return redirect(url_for('registro'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users_collection.insert_one({
            'username': username,
            'email': email,
            'password': hashed_password,
            'created_at': datetime.utcnow(),  # Fecha de registro
            'profile_pic': None  # Inicialmente sin foto de perfil
        })

        flash('Registro exitoso. Por favor, inicia sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('registro.html')

# Ruta para actualizar la foto de perfil
@app.route('/update_profile_pic', methods=['POST'])
def update_profile_pic():
    if 'username' not in session:
        return redirect(url_for('login'))

    file = request.files.get('profile_pic')
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        content_type = file.content_type
        profile_pic_data = {
            'data': binary.Binary(file.read()),
            'filename': filename,
            'content_type': content_type
        }
        users_collection.update_one(
            {'username': session['username']},
            {'$set': {'profile_pic': profile_pic_data}}
        )
        flash('Foto de perfil actualizada exitosamente', 'success')
    else:
        flash('Archivo no válido. Usa PNG, JPG o JPEG.', 'error')
    return redirect(url_for('perfil'))

# Ruta para el perfil del usuario
@app.route('/perfil')
def perfil():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = users_collection.find_one({'username': username})
    if not user:
        flash('Usuario no encontrado', 'error')
        return redirect(url_for('index'))

    # Total de publicaciones, likes y comentarios (asumiendo que ya lo calculas)
    total_posts = posts_collection.count_documents({'username': username})
    total_likes = sum(post['likes'].count(username) for post in posts_collection.find())
    total_comments = sum(len(post.get('comments', [])) for post in posts_collection.find({'username': username}))

    # Comunidades creadas por el usuario
    created_communities = list(comunidades_collection.find({'creator': username}))
    for comm in created_communities:
        comm['_id'] = str(comm['_id'])

    # Comunidades a las que está unido el usuario
    joined_communities = list(comunidades_collection.find({'members': username}))
    for comm in joined_communities:
        comm['_id'] = str(comm['_id'])

    return render_template('perfil.html', user=user, total_posts=total_posts, total_likes=total_likes, total_comments=total_comments, created_communities=created_communities, joined_communities=joined_communities)

# Ruta para servir la foto de perfil desde MongoDB
@app.route('/profile_pic/<username>')
def serve_profile_pic(username):
    user = users_collection.find_one({'username': username})
    if user and 'profile_pic' in user:
        return send_file(
            io.BytesIO(user['profile_pic']['data']),
            mimetype=user['profile_pic']['content_type'],
            as_attachment=False,
            download_name=user['profile_pic']['filename']
        )
    # Imagen predeterminada si no hay foto de perfil
    return send_file('static/Kirby.webp', mimetype='image/webp')

# Ruta de configuración (mostrar formulario)
@app.route('/configuracion', methods=['GET'])
def configuracion():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'username': session['username']})
    if not user:
        return redirect(url_for('login'))

    return render_template('configuracion.html', user=user)

# Ruta para guardar cambios de configuración
@app.route('/update_config', methods=['POST'])
def update_config():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = users_collection.find_one({'username': session['username']})
    if not user:
        return redirect(url_for('login'))

    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm-password')

    # Validaciones
    if email and email != user['email']:
        if users_collection.find_one({'email': email}):
            flash('El correo electrónico ya está en uso', 'error')
            return redirect(url_for('configuracion'))
        users_collection.update_one(
            {'username': session['username']},
            {'$set': {'email': email}}
        )

    if password and confirm_password:
        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'error')
            return redirect(url_for('configuracion'))
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users_collection.update_one(
            {'username': session['username']},
            {'$set': {'password': hashed_password}}
        )

    flash('Configuración actualizada exitosamente', 'success')
    return redirect(url_for('configuracion'))

# Ruta para eliminar la cuenta
@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    
    # Eliminar todas las publicaciones del usuario
    posts_collection.delete_many({'username': username})
    
    # Eliminar el usuario
    users_collection.delete_one({'username': username})
    
    # Cerrar la sesión
    session.pop('username', None)
    flash('Tu cuenta ha sido eliminada permanentemente', 'success')
    return redirect(url_for('index'))

# Ruta de login (maneja GET y POST)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username']  # Puede ser username o email
        password = request.form['password']

        # Buscar al usuario por username o email
        user = users_collection.find_one({
            '$or': [
                {'username': username_or_email},
                {'email': username_or_email}
            ]
        })

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['username'] = user['username']  # Guarda el nombre de usuario en la sesión
            return redirect(url_for('index'))  # Redirige a la página principal
        else:
            flash('Usuario o contraseña incorrectos', 'error')
            return redirect(url_for('login'))

    # Si es GET, muestra el formulario de inicio de sesión
    return render_template('login.html')

# Ruta de logout
@app.route('/logout')
def logout():
    session.pop('username', None)  # Cierra la sesión
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)