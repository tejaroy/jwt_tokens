from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid # for public id
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_jwt_extended import *

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
class User(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	public_id = db.Column(db.String(50), unique = True)
	name = db.Column(db.String(100))
	email = db.Column(db.String(70), unique = True)
	password = db.Column(db.String(80))

def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = request.headers.get('Authorization')
		if not token:
			return jsonify({'message' : 'Token is missing !!'}), 401
		try:
			payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
			current_user = User.query\
				.filter_by(id = payload['id'])\
				.first()
		except Exception as e :
			return jsonify({
				'message' : 'Token is invalid !!'
			}), 401

		return f(current_user,*args, **kwargs)

	return decorated

@app.route('/user', methods =['GET'])
@token_required
def get_all_users(current_user):
	users = User.query.filter_by(id=current_user.id).all()
	output = []
	for user in users:
		output.append({
			'public_id': user.public_id,
			'name' : user.name,
			'email' : user.email
		})
	return jsonify({'users': output})

@app.route('/login', methods =['POST'])
def login():
	auth = request.form

	if not auth or not auth.get('email') or not auth.get('password'):
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
		)

	user = User.query\
		.filter_by(email = auth.get('email'))\
		.first()

	if not user:
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
		)

	if check_password_hash(user.password, auth.get('password')):
		token = jwt.encode({
			'id': user.id,
			'exp' : datetime.utcnow() + timedelta(minutes = 15)
		},app.config['SECRET_KEY'])
		refresh_token=jwt.encode({
			"id":user.id,
			"exp":datetime.utcnow()+timedelta(minutes=30)
		},app.config['SECRET_KEY'])
		return make_response(jsonify({
			"token":token},{
			"refresh_token":refresh_token
		}))
	return make_response(
		'Could not verify',
		403,
		{'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
	)

@app.route('/signup', methods =['POST'])
def signup():
	data = request.form

	name, email = data.get('name'), data.get('email')
	password = data.get('password')

	user = User.query\
		.filter_by(email = email)\
		.first()
	if not user:
		user = User(
			public_id = str(uuid.uuid4()),
			name = name,
			email = email,
			password = generate_password_hash(password)
		)
		db.session.add(user)
		db.session.commit()


		return make_response('Successfully registered.', 201)
	else:
		return make_response('User already exists. Please Log in.', 202)


@app.route('/refresh',methods=['POST'])
def refresh():
	data = request.form
	if not data or not data.get('refresh_token'):
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate': 'Basic realm ="Login required !!"'}
		)
	jwt_data = jwt.decode(data.get('refresh_token'), options={"verify_signature": False})
	user = User.query \
		.filter_by(id=jwt_data['id']) \
		.first()
	print(user.id)
	print(jwt_data['id'])

	if not user:
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
		)
	if user:
		token = jwt.encode({
			"id":user.id,
			'exp': datetime.utcnow() + timedelta(minutes=30)
		}, app.config['SECRET_KEY'])
		refresh_token = jwt.encode({
			"id": user.id,
			"exp": datetime.utcnow() + timedelta(minutes=60)
		}, app.config['SECRET_KEY'])
		return make_response(jsonify({
			"token": token}, {
			"refresh_token": refresh_token
		}))
	return make_response(
		'Could not verify',
		403,
		{'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
	)

if __name__ == "__main__":
	app.run(debug = True)
