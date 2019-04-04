#!flask/bin/python
from flask import jsonify, abort, make_response, request, url_for, render_template, flash, redirect
from flask_login import login_user, current_user, logout_user
from flask import request
from sqlalchemy import update

import uuid  # Key generation
from functools import wraps  # decorator wrapping
import datetime
import time  # for key expiration
import bcrypt  # password hashing
import json

from pprint import pprint

# package stuff
from flask_api.forms import RegistrationForm, LoginForm, GenerateKeyForm
from flask_api.models import users, apikeys
from flask_api import app, db, KEY_DURATION_SECS, SALT_ROUNDS

# Sample db
# from Miguel Grinberg
tasks = [
    {
        'id': 1,
        'title': u'Buy groceries',
        'description': u'Milk, Cheese, Pizza, Fruit, Tylenol',
        'done': False
    },
    {
        'id': 2,
        'title': u'Learn Python',
        'description': u'Need to find a good Python tutorial on the web',
        'done': False
    }
]

####################
# Helper Functions #
####################

# replaces id field with a URI(Universal Resource Identifier)
def make_public_task(task):
    new_task = {}
    for field in task:
        if(field == 'id'):
            new_task['uri'] = url_for(
                'get_task', task_id=task['id'], _external=True)
        else:
            new_task[field] = task[field]
    return new_task

#
def key_expired(key):
    found_key = apikeys.query.filter_by(key=key).first()
    if(found_key):  # if key is valid
        cur_time = int(time.mktime(datetime.datetime.now().timetuple()))
        if(found_key.expiration > int(cur_time) or found_key.expiration == -1):
            return False
    else:
        print("No Key Found In DB")
    return True

#key check decorator
def key_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if('api_key' in request.args):
            key = request.args.get('api_key')
            if(not key_expired(key)):  # if key is valid
                return func(*args, **kwargs)  # do normal func
            else:
                return make_response(jsonify({'error': 'Key Expired'}), 401)
        abort(401)  # if no key or key invalid return 401
    return inner

# generate random universally unique identifier
def generate_key():
    return str(uuid.uuid4())

	
####################
#   Error Pages    #
####################
	
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


@app.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({'error': 'Bad Request'}), 400)


@app.errorhandler(401)
def unauthorised_access(error):
    # 401 makes a login popup, 403 doesn't
    return make_response(jsonify({'error': 'Unauthorised access'}), 401)

# authentication error used by HTTPBasicAuth
# @auth.error_handler
# def unauthorised(): #Used by HTTPBasicAuth
#    return make_response(jsonify({'error': 'Unauthorised access'}), 403) # 401 makes a login popup, 403 doesn't


####################
#      Routes      #
####################

# index
@app.route('/', methods=['GET'])
def index():
    return render_template('home.html', title='Home')

# Documentation and api execution page
@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html', title='About')

# Documentation and api execution page
@app.route('/docs', methods=['GET', 'POST'])
def docs():
    test = {"tasks": [{"description": "Milk, Cheese, Pizza, Fruit, Tylenol", "done": False, "title": "Buy groceries", "uri": "http://127.0.0.1:5000/todo/api/v1/tasks/1"},
                      {"description": "Need to find a good Python tutorial on the web", "done": False, "title": "Learn Python", "uri": "http://127.0.0.1:5000/todo/api/v1/tasks/2"}]}

    return render_template('docs.html', title='Documentation', data=json.dumps(test, indent=4, sort_keys=True))

# Profile
# this is where you see your details and generate new keys
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if current_user.is_authenticated:
        form = GenerateKeyForm()
        if form.validate_on_submit():
            cur_time = time.mktime(datetime.datetime.now().timetuple())
            expiration = int(cur_time + KEY_DURATION_SECS)

            if (len(current_user.api_key) > 0):
                apikeys.query.filter_by(user_id=current_user.id).update(dict(
                    key=generate_key(), expiration=expiration, user_id=current_user.id, active=True))
            else:
                key = apikeys(key=generate_key(), expiration=expiration,
                              user_id=current_user.id, active=True)
                current_user.api_key.append(key)
            db.session.commit()

        if (len(current_user.api_key) > 0):
            expiration_str = time.strftime(
                '%a, %b %d, %Y @ %I:%M%p', time.localtime(current_user.api_key[0].expiration))
            ex = key_expired(current_user.api_key[0].key)
        else:
            expiration_str = ''
            ex = False
        return render_template('profile.html', title='Profile', form=form, expiration_str=expiration_str, expired=ex)
    else:
        return redirect(url_for('login'))
    return render_template('profile.html', title='Profile')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if(current_user.is_authenticated):
        flash(f'Please log out before registering.', 'info')
        return redirect(url_for('index'))

    form = RegistrationForm()
    if(form.validate_on_submit()):
        hashed_pw = bcrypt.hashpw(
            form.password.data.encode(), bcrypt.gensalt(SALT_ROUNDS))
        # hashed_pw = bcrypt.generate_password_hash(form.password.data.encode(), rounds=15)
        user = users(username=form.username.data,
                     email=form.email.data.lower(), password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        # users.append({'username':form.username.data, 'password':hashed_pw, 'email':form.email.data.lower(), 'api_key':''})
        flash(f'Account created for {form.username.data}!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if(current_user.is_authenticated):
        flash(f'Already logged in.', 'info')
        return redirect(url_for('index'))

    form = LoginForm()
    if(form.validate_on_submit()):
        # find account with that email
        # SELECT FROM users WHERE email=form.email.data
        user = users.query.filter_by(email=form.email.data.lower()).first()
        if(user):  # if valid
            hashed_pw = bcrypt.hashpw(
                form.password.data.encode(), user.password)
            if(hashed_pw == user.password):
                login_user(user)
                flash(f'Logged in to {user.username}!', 'success')
                return redirect(url_for('index'))
        flash(f'Incorrect Email or Password.', 'danger')
    return render_template('login.html', title='Login', form=form)

# Logout
@app.route('/logout', methods=['GET'])
def logout():
    if(current_user.is_authenticated):
        cur = current_user.username
        logout_user()
        # flash(f'Logged out of {cur}!', 'success')
    return redirect(url_for('index'))

	
####################
#  API Endpoints   #
####################

# All Tasks
@app.route('/todo/api/v1/tasks', methods=['GET'])
@key_required
def get_tasks():
    # returns all tasks and gives them a URI
    return jsonify({'tasks': [make_public_task(task) for task in tasks]})
    # return jsonify({'tasks': tasks})

# Specific Task


@app.route('/todo/api/v1/tasks/<int:task_id>', methods=['GET'])
@key_required
def get_task(task_id):
    task = [task for task in tasks if task['id'] == task_id]
    if(len(task) == 0):
        abort(404)
    # return jsonify({'task': task[0]})
    # gives URI which is not needed but whatever
    return jsonify({'task': make_public_task(task[0])})

# Posting to Tasks List
@app.route('/todo/api/v1/tasks', methods=['POST'])
@key_required
def create_task():
    # if post is invalid abort
    if not request.json or not 'title' in request.json:
        abort(400)
    # otherwise construct a new task using the given json
    task = {
        'id': tasks[-1]['id'] + 1,
        'title': request.json['title'],
        'description': request.json.get('description', ""),
        'done': False
    }
    tasks.append(task)

    # returns newely created task back with a status code and URI
    # 201 = success, request has been fulfilled
    return jsonify({'task': make_public_task(task)}), 201

# Deleting Task ID
@app.route('/todo/api/v1/tasks/<int:task_id>', methods=['DELETE'])
@key_required
def delete_task(task_id):
    try:
        tasks.pop(task_id)
    except Exception as e:
        print(e)
        abort(400)
    return make_response(jsonify({'success': 'Task Deleted'}), 200)

# Updating Task ID
@app.route('/todo/api/v1/tasks/<int:task_id>', methods=['PUT'])
@key_required
def update_task(task_id):
    # if post is invalid abort
    if not request.json:
        abort(400)
    try:
        # Validate that they actually sent before getting
        if('title' in request.json):
            tasks[task_id-1]['title'] = request.json.get('title')
        if('description' in request.json):
            tasks[task_id-1]['description'] = request.json.get('description')
        if('done' in request.json):
            tasks[task_id-1]['done'] = request.json.get('done')
    except Exception as e:
        print(e)
        abort(400)
    # Return changed task back with a URI
    return jsonify({'task': make_public_task(tasks[task_id-1])}), 201