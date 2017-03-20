import sqlite3
from flask import request, g

DATABASE = 'schoolproject.db'

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

def query_db2(query, args):
    cur = db().execute(query, args)
    db().commit()
    cur.close()

def islogin():
    if request.cookies.get('username') == None or request.cookies.get('password') == None:
        return False
    else:
        return True

def isuser(username, password):
    result = query_db('SELECT * FROM users WHERE username = ? and password = ?', [username, password], True)
    if result == None:
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