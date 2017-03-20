#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, render_template, make_response, redirect, request, send_from_directory, Markup, send_file
from werkzeug.utils import secure_filename
import os, datetime, hashlib
import logging, ssl
import functions, arrays
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'content'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

def app_settings():
    user = functions.get_user()
    is_login = functions.islogin()
    title = 'Теми за държавен изпит'
    unicode = 'utf8'
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

    return title, unicode, menu, adminmenu

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/', methods=['GET', 'POST'])
def index():
    find_username = request.cookies.get('username')
    find_password = request.cookies.get('password')
    args = {
        'path': request.url_root,
        'url': request.url,
        'app_settings': app_settings(),
        'categories': arrays.categories(),
        'username': find_username,
        'profile': functions.get_user(),
    }
    if find_username and find_password:
        return render_template('index.html', **args)
    else:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            hashed_password = hashlib.md5(password.encode('utf8')).hexdigest()
            if username != "" and password != "":
                if functions.isuser(username, hashed_password):
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
                return render_template('login.html', error=error)
        return render_template('login.html')

@app.route('/admin/')
@app.route('/admin/<page>/')
@app.route('/admin/<page>/<task>/', methods=['GET', 'POST'])
def admin(page=None, task=None):
    args = {
        'app_settings': app_settings(),
        'stats': arrays.stats(),
        'categories': arrays.categories(),
        'mcats': arrays.mcategories(),
        'users': arrays.users(),
        'subcats': arrays.scategories()
    }
    user = functions.get_user()
    if not functions.islogin() or user[0]["privileges"] == 0:
        red = make_response(redirect('/'))
        return red
    if page == None:
        return render_template('admin.html', **args)
    elif page == 'categories':
        if task == 'addm' and request.method == 'POST':
            return render_template('/admin/categories.html', **args)
        elif task == 'add' and request.method == 'POST':
            return render_template('/admin/categories.html', **args)
        elif task == 'edit' and request.method == 'POST':
            return render_template('/admin/categories.html', **args)
        elif task == 'delete' and request.method == 'POST':
            return render_template('/admin/categories.html', **args)
        else:
            return render_template('/admin/categories.html', **args)
    elif page == 'users':
        if task == 'add' and request.method == 'POST':
            username = request.form["username"]
            password = hashlib.md5(request.form["password"].encode('utf8')).hexdigest()
            privilege = request.form["privilege"]
            if username == "" or password == "":
                msg = "Моля попълнете всички полета"
            else:
                msg = "Потребителя е добавен"
                functions.query_db2("INSERT INTO users (username, password, privileges) VALUES (?, ?, ?)", [username, password, privilege])
            return render_template('/admin/users.html', **args, msg=msg)
        elif task == 'edit' and request.method == 'POST':
            return render_template('/admin/users.html', **args)
        elif task == 'delete' and request.method == 'POST':
            return render_template('/admin/users.html', **args)
        else:
            return render_template('/admin/users.html', **args)
    elif page == 'topics':
        if task == 'add' and request.method == 'POST':
            title = request.form['title']
            text = request.form['text']
            cat = request.form['cat']
            if 'file' in request.files:
                file = request.files['file']
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            else:
                filename = ""
            if title == "" or text == "":
                msg = "Моля попълнете всички полета"
            else:
                print(filename)
                msg = "Темата е добавена"
                functions.query_db2("INSERT INTO topics (title, text, cat, linked_upload) VALUES (?, ?, ?, ?)", [title, text, cat, filename])
            return render_template('/admin/topics.html', **args, msg=msg)
        else:
            return render_template('/admin/topics.html', **args)

@app.route('/logout/')
def logout():
    response = make_response(redirect('/'))
    response.set_cookie('username', expires=0)
    response.set_cookie('password', expires=0)
    return response

@app.route('/categories/<int:cat_id>/')
def categorys(cat_id):
    if functions.islogin() == False:
        return render_template('login.html')
    topics = []
    args = {
        'path': request.url_root,
        'url': request.url,
        'app_settings': app_settings(),
        'categories': arrays.categories(),
        'topics': topics,
        'profile': functions.get_user()
    }
    for row in functions.query_db('SELECT id, title FROM topics WHERE cat = ?', [cat_id]):
        topic = {}
        topic["title"] = row["title"]
        topic["id"] = row["id"]
        topics.append(topic)
    return render_template('categories.html', **args)

@app.route('/view/<int:topic_id>/')
@app.route('/view/<int:topic_id>/<task>/')
def view_topic(topic_id, task=None):
    print_topic = []
    args = {
        'path': request.url_root,
        'url': request.url,
        'app_settings': app_settings(),
        'categories': arrays.categories(),
        'profile': functions.get_user(),
        'topic': print_topic
    }
    if functions.islogin() == False:
        return render_template('login.html')
    if task == '':
        user = functions.get_user()
        if user[0]["privileges"] == 0:
            red = make_response(redirect('/'))
            return red
        else:
            return render_template('view.html', **args)
    topic = {}
    for row in functions.query_db('SELECT * FROM topics WHERE id = ? Limit 1', [topic_id]):
        topic["title"] = Markup(row["title"])
        topic["text"] = Markup(row["text"])
        topic["id"] = row["id"]
        topic["upload"] = row["linked_upload"]
    print_topic.append(topic)

    return render_template('view.html', **args)

@app.route('/download/<filename>')
def download(filename):
    if functions.islogin() == False:
        return render_template('login.html')

    path_filename = './content/%s' % filename
    return send_file(path_filename, as_attachment=True)

@app.errorhandler(404)
def not_found(error):
    red = make_response(redirect('/'))
    return red

if __name__ == "__main__":
    #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    #context.load_cert_chain('/ssl/host.crt', '/ssl/aiae.key')

    app.run(debug=True, port=7294, ssl_context=None, threaded=False, host='0.0.0.0')
