#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, render_template, make_response, redirect, request, send_from_directory, g, Markup
from werkzeug.utils import secure_filename
import os, sqlite3, datetime, hashlib
import logging, json
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
UPLOAD_FOLDER = 'content'
DATABASE = 'schoolproject.db'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

def check_if_login():
    if request.cookies.get('username') == None or request.cookies.get('password') == None:
        return False
    else:
        return True

def get_user():
    profile = []
    for row in query_db('SELECT * FROM users WHERE username = ? and password = ?', [request.cookies.get('username'), request.cookies.get('password')]):
        settings = {}
        settings["username"] = row["username"]
        settings["privileges"] = row["privileges"]
        profile.append(settings)
    return profile

def app_settings():
    user = get_user()
    is_login = check_if_login()
    title = 'Теми за държавен изпит'
    uncode = 'utf8'
    menu = [
        {"url" : "/", "name" : "Начало"},
    ]

    if user[0]["privileges"] == 1:
        menu += [
            {"url": "/admin", "name": "Админ панел"}
        ]

    if is_login:
        menu += [
            {"url" : "/logout/", "name" : "Излизане"}
        ]

    adminmenu = [
        {"url": "/admin/categories/", "name": "Категории"},
        {"url": "/admin/topics/", "name": "Добави урок"},
        {"url": "/admin/users/", "name": "Потребители"},
        {"url": "/", "name": "Към сайта"},
    ]

    return title, uncode, menu, adminmenu

def db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def query_db(query, args=(), one=False):
    cur = db().execute(query, args)
    cur.row_factory = sqlite3.Row
    rv = cur.fetchall()
    cur.close()
    return (rv if rv else None) if one else rv

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def finduser(username, password):
    result = query_db('SELECT * FROM users WHERE username = ? and password = ?', [username, password], True)
    if result == None:
        return False
    else:
        return True

def show_categories():
    print_cats = []
    for row in query_db('SELECT id, name FROM categories'):
        cats = {}
        sub_cat = []
        for row2 in query_db('SELECT * FROM sub_categories WHERE cat_id = ?', [row["id"]]):
            test = {}
            test["id"] = row2["id"]
            test["name"] = row2["name"]
            sub_cat.append(test)
            cats["sub"] = sub_cat
        cats["id"] = row["id"]
        cats["name"] = row["name"]
        print_cats.append(cats)
    return print_cats

def print_subcategories():
    print_cats = []
    for row in query_db('SELECT id, name FROM sub_categories'):
        cat = {}
        cat["id"] = row["id"]
        cat["name"] = row["name"]
        print_cats.append(cat)
    return print_cats

def db_stats():
    stats = []
    for row in query_db('SELECT * FROM sqlite_sequence'):
        r = {}
        r["name"] = row["name"]
        r["count"] = row["seq"]
        stats.append(r)
    return stats

@app.route('/', methods=['GET', 'POST'])
def index():
    find_username = request.cookies.get('username')
    find_password = request.cookies.get('password')
    if find_username and find_password:
        return render_template('index.html', path=request.url_root, url=request.url, app_settings=app_settings(), categorys=show_categories(), username=find_username, profile=get_user())
    else:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            hashed_password = hashlib.md5(password.encode('utf8')).hexdigest()
            if username != "" and password != "":
                if finduser(username, hashed_password):
                    expire_date = datetime.datetime.now()
                    expire_date = expire_date + datetime.timedelta(days=90)
                    response = make_response(redirect('/'))
                    response.set_cookie('username', username, expires=expire_date)
                    response.set_cookie('password', hashed_password, expires=expire_date)
                    return response
                else:
                    error = 'Потребителскто име или парола не са намерени.'
                    return render_template('login.html', error=error)
            else:
                error = 'Моля попълнете всички полета.'
        return render_template('login.html')

@app.route('/admin/')
@app.route('/admin/<page>/')
@app.route('/admin/<page>/<task>/')
def adminpanel(page=None, task=None):
    user = get_user()
    if not check_if_login() or user[0]["privileges"] == 0:
        red = make_response(redirect('/'))
        return red
    if page == None:
        return render_template('adminpanel.html', app_settings=app_settings(), stats=db_stats())
    elif page == 'categories':
        if task == None:
            return render_template('/admin/categories.html', app_settings=app_settings(), categorys=show_categories())
        elif task == 'add':
            return render_template('/admin/categories.html', app_settings=app_settings())
        elif task == 'edit':
            return render_template('/admin/categories.html', app_settings=app_settings())
        elif task == 'delete':
            return render_template('/admin/categories.html', app_settings=app_settings())
    elif page == 'users':
        if task == None:
            return render_template('/admin/users.html', app_settings=app_settings())
        elif task == 'add':
            return render_template('/admin/users.html', app_settings=app_settings())
        elif task == 'edit':
            return render_template('/admin/users.html', app_settings=app_settings())
        elif task == 'delete':
            return render_template('/admin/users.html', app_settings=app_settings())
    elif page == 'topics':
        return render_template('/admin/topics.html', app_settings=app_settings(), subcats=print_subcategories())

@app.route('/logout/')
def logout():
    response = make_response(redirect('/'))
    response.set_cookie('username', expires=0)
    response.set_cookie('password', expires=0)
    return response

@app.route('/categorys/<int:cat_id>/')
def categorys(cat_id):
    if check_if_login() == False:
        return render_template('login.html')
    topics = []
    for row in query_db('SELECT id, title FROM topics WHERE cat = ?', [cat_id]):
        topic = {}
        topic["title"] = row["title"]
        topic["id"] = row["id"]
        topics.append(topic)
    return render_template('categorys.html', path=request.url_root, url=request.url, app_settings=app_settings(), categorys=show_categories(), topics=topics, profile=get_user())

@app.route('/view/<int:topic_id>/')
def view_topic(topic_id):
    if check_if_login() == False:
        return render_template('login.html')
    print_topic = []
    topic = {}
    for row in query_db('SELECT * FROM topics WHERE id = ? Limit 1', [topic_id]):
        topic["title"] = Markup(row["title"])
        topic["text"] = Markup(row["text"])
        topic["id"] = row["id"]

    print_topic.append(topic)
    return render_template('view.html', path=request.url_root, url=request.url, app_settings=app_settings(), categorys=show_categories(), topic=print_topic, profile=get_user())

@app.route('/upload_files/', methods=['GET', 'POST'])
def upload_files():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return render_template('upload.html', path=request.url_root, url=request.url)

@app.errorhandler(404)
def not_found(error):
    red = make_response(redirect('/'))
    return red

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=69)
