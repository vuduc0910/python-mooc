import datetime

from flask import Flask, redirect, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from flask_mail import Mail, Message
import random

app = Flask(__name__)

api = Api(app)
app.config['SECRET_KEY'] = 'JWT-VUDUC'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'danhnguyen.cms@gmail.com'
app.config['MAIL_PASSWORD'] = 'Minhtam@0910'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

db = SQLAlchemy(app)
mail = Mail(app)


# models
# users:

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50))
    public_id = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)
    email = db.Column(db.String(50), unique=True)


class Coffee(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    public_id = db.Column(db.String(50))
    name = db.Column(db.String(50))
    category = db.Column(db.String(50))
    description = db.Column(db.String(100))
    price = db.Column(db.Integer)

def middleware(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'authorization' in request.headers:
            token = request.headers['authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@middleware
def getAllUser(current_user):
    if not current_user.admin:
        return jsonify({'message': 'No permission to perform this function'})
    users = User.query.all()
    res = []
    for user in users:
        data = {}
        data['name'] = user.name
        data['publicId'] = user.public_id
        data['password'] = user.password
        data['isAdmin'] = user.admin
        data['email'] = user.email
        res.append(data)
    return jsonify({"data": res})


@app.route('/user/<id>', methods=['GET'])
@middleware
def getUserById(current_user, id):
    if not current_user.admin:
        return jsonify({'message': 'No permission to perform this function'})
    user = User.query.filter_by(public_id=id).first()
    if not user:
        return jsonify({'message': 'Not found'})
    res = {}
    res['public_id'] = user.public_id
    res['name'] = user.name
    res['password'] = user.password
    res['isAdmin'] = user.admin
    res['email'] = user.email
    return jsonify({"data": res})


@app.route('/user', methods=['POST'])
def creatUser():
    data = request.get_json()
    password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=password, admin=False, email=data['email'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'created'})


@app.route('/user/<id>', methods=['PUT'])
@middleware
def updateUser(current_user, id):
    if not current_user.admin and current_user.public_id != id:
        return jsonify({'message': 'No permission to perform this function'})

    user = User.query.filter_by(public_id=id).first()
    if not user:
        return jsonify({'message': 'Not found'})
    data = request.get_json()
    user.password = generate_password_hash(data['password'], method='sha256')
    db.session.commit()
    return jsonify({'message': 'Updated'})


@app.route('/user/<id>', methods=['DELETE'])
@middleware
def deleteUser(current_user, id):
    if not current_user.admin:
        return jsonify({'message': 'No permission to perform this function'})
    user = User.query.filter_by(public_id=id).first()
    if not user:
        return jsonify({'message': 'Not found'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'Updated'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response("Couldn't verify", 401, {'WWW-Authenticate': 'Basic realm="Login required"'})
    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return jsonify({"message": 'Not found'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})
    return make_response("Couldn't verify", 401, {'WWW-Authenticate': 'Basic realm="Login required"'})


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    number = random.randint(100001, 999998)
    email = data['email']
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": 'Not found'})
    msg = Message('Reset password', sender='danhnguyen.cms@gmail.com', recipients=[email])
    msg.body = 'verify with number {}'.format(number)
    mail.send(msg)
    return jsonify({'message': number})


# Product

@app.route('/product', methods=['POST'])
@middleware
def create_product(current_user):
    if not current_user.admin and current_user.public_id != id:
        return jsonify({'message': 'No permission to perform this function'})
    data = request.get_json()
    name = data['name']
    description = data['description']
    category = data['category']
    price = data['price']
    new_product = Coffee(public_id=str(uuid.uuid4()), name=name, description=description, category=category, price=price)
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'created'})


@app.route('/product/<id>', methods=['PUT'])
@middleware
def update_product(current_user):
    if not current_user.admin :
        return jsonify({'message': 'No permission to perform this function'})
    data = request.get_json()
    product = Coffee.query.filter_by(public_id=id).first()
    product.name = data['name']
    product.description = data['description']
    product.category = data['category']
    product.price = data['price']
    db.session.commit()
    return jsonify({'message': 'Updated'})


@app.route('/product/<id>', methods=['DELETE'])
@middleware
def delete_product(current_user):
    if not current_user.admin :
        return jsonify({'message': 'No permission to perform this function'})
    product = Coffee.query.filter_by(public_id=id).first()
    if not product:
        return jsonify({'message': 'Not found'})
    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Updated'})


@app.route('/product/search', methods=['POST'])
def get_list_product():
    args = request.args
    limit = args.limit
    offset = args.offset
    data = request.json()
    products = Coffee.query.filter_by(public_id.like("%{}%".format(data['id'])),
                                      name.like("%{}%".format(data['name'])),
                                      description.like("%{}%".format(data['description']))).limit(limit).offset(offset)
    return jsonify({'data': []})


if __name__ == '__main__':
    app.run(debug=True)
