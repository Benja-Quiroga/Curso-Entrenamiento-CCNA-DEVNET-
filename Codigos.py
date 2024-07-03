from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256

# Inicializa la aplicación Flask
app = Flask(__name__)

# Configuración de la base de datos SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializa la extensión SQLAlchemy
db = SQLAlchemy(app)

# Definición del modelo de usuario
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellido = db.Column(db.String(100), nullable=False)
    registro = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = pbkdf2_sha256.hash(password)

    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password_hash)

# Ruta para registrar nuevos usuarios
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    nombre = data.get('nombre')
    apellido = data.get('apellido')
    registro = data.get('registro')
    password = data.get('password')

    # Verificación de datos faltantes
    if not all([nombre, apellido, registro, password]):
        return jsonify({"message": "Faltan datos"}), 400

    # Creación de un nuevo usuario
    user = User(nombre=nombre, apellido=apellido, registro=registro)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Usuario registrado"}), 201

# Ruta para el login de usuarios
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    nombre = data.get('nombre')
    apellido = data.get('apellido')
    password = data.get('password')

    # Búsqueda de usuario por nombre y apellido
    user = User.query.filter_by(nombre=nombre, apellido=apellido).first()

    # Verificación de la contraseña
    if user and user.check_password(password):
        return jsonify({"message": "Login exitoso"}), 200
    else:
        return jsonify({"message": "Credenciales incorrectas"}), 401

# Inicio de la aplicación
if __name__ == "__main__":
    # Crea la base de datos y las tablas si no existen
    with app.app_context():
        db.create_all()
    
    # Ejecuta la aplicación en el puerto 8500
    app.run(port=8500)

