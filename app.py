import bcrypt
from flask import Flask, request, jsonify
from models.user import User
from models.meal import Meal
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

app = Flask(__name__)
app.config['SQLALCHEMY_ECHO'] = True
app.config['SECRET_KEY'] = "mysecretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@localhost:3306/flask-crud'

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({ "message": "Logged out successfully" }), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({ "error": "Missing username or password" }), 400
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({ "error": "Invalid username or password." }), 401
    if not bcrypt.checkpw(str.encode(password), str.encode(user.password)):
        return jsonify({ "error": "Invalid username or password." }), 401
    login_user(user)
    return jsonify({ "message": "Logged in successfully" }), 200

@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({ "error": "Missing username or password" }), 400
    hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
    user = User(username=username, password=hashed_password, role="user")
    db.session.add(user)
    db.session.commit()
    return jsonify({ "message": "User created successfully" }), 201

@app.route('/user/<int:id>', methods=['GET'])
@login_required
def get_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({ "error": "User not found" }), 404
    return jsonify({ "id": user.id, "username": user.username }), 200

@app.route('/user/<int:id>', methods=['PUT'])
@login_required
def update_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({ "error": "User not found" }), 404
    if id != current_user.id and current_user.role != "admin":
        return jsonify({ "error": "Forbidden" }), 403
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if username:
        user.username = username
    if password:
        user.password = password
    db.session.commit()
    return jsonify({ "message": "User updated successfully" }), 200

@app.route('/user/<int:id>', methods=['DELETE'])
@login_required
def delete_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({ "error": "User not found" }), 404
    if id != current_user.id and current_user.role != "admin":
        return jsonify({ "error": "Forbidden" }), 403
    db.session.delete(user)
    db.session.commit()
    return jsonify({ "message": "User deleted successfully" }), 200

@app.route('/meals', methods=['POST'])
@login_required
def create_meal():
    data = request.get_json()
    name = data.get('name')
    description = data.get('description', "")
    timestamp = data.get('timestamp')
    on_diet = data.get('on_diet')
    if not name or not description or not timestamp or not on_diet:
        return jsonify({ "error": "Missing name or description or timestamp or on_diet" }), 400
    meal = Meal(name=name, description=description, timestamp=timestamp, on_diet=on_diet, user=current_user)
    db.session.add(meal)
    db.session.commit()
    return jsonify({ "message": "Meal created successfully" }), 201

@app.route('/meals/<int:id>', methods=['GET'])
@login_required
def get_meal(id):
    meal = Meal.query.get(id)
    if not meal or meal.user_id != current_user.id:
        return jsonify({ "error": "Meal not found" }), 404
    return jsonify({ 
        "id": meal.id, 
        "name": meal.name, 
        "description": meal.description, 
        "timestamp": meal.timestamp, 
        "on_diet": meal.on_diet 
    }), 200

@app.route('/meals/<int:id>', methods=['PUT'])
@login_required
def update_meal(id):
    meal = Meal.query.get(id)
    if not meal or meal.user_id != current_user.id:
        return jsonify({ "error": "Meal not found" }), 404
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    timestamp = data.get('timestamp')
    on_diet = data.get('on_diet')
    if name:
        meal.name = name
    if description:
        meal.description = description
    if timestamp:
        meal.timestamp = timestamp
    if on_diet:
        meal.on_diet = on_diet
    db.session.commit()
    return jsonify({ "message": "Meal updated successfully" }), 200

@app.route('/meals/<int:id>', methods=['DELETE'])
@login_required
def delete_meal(id):
    meal = Meal.query.get(id)
    if not meal or meal.user_id != current_user.id:
        return jsonify({ "error": "Meal not found" }), 404
    db.session.delete(meal)
    db.session.commit()
    return jsonify({ "message": "Meal deleted successfully" }), 200

@app.route('/meals', methods=['GET'])
def get_meals():
    meals = Meal.query.filter_by(user_id = current_user.id).all()
    meals_list = [
        { 
            "id": meal.id, 
            "name": meal.name, 
            "description": meal.description, 
            "timestamp": meal.timestamp, 
            "on_diet": meal.on_diet 
        }
        for meal in meals
    ]
    return jsonify(meals_list), 200

if __name__ == '__main__':
    app.run(debug=True)