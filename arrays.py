import functions

def categories():
    categories = []
    for row in functions.query_db('SELECT id, name FROM categories'):
        category = {}
        scategory = []
        for row2 in functions.query_db('SELECT * FROM sub_categories WHERE cat_id = ?', [row["id"]]):
            temp = {}
            temp["id"] = row2["id"]
            temp["name"] = row2["name"]
            scategory.append(temp)
            category["sub"] = scategory
        category["id"] = row["id"]
        category["name"] = row["name"]
        categories.append(category)
    return categories

def mcategories():
    categories = []
    for row in functions.query_db('SELECT id, name FROM categories'):
        category = {}
        category["id"] = row["id"]
        category["name"] = row["name"]
        categories.append(category)
    return categories

def scategories():
    categories = []
    for row in functions.query_db('SELECT id, name FROM sub_categories'):
        category = {}
        category["id"] = row["id"]
        category["name"] = row["name"]
        categories.append(category)
    return categories

def users():
    users = []
    for row in functions.query_db('SELECT * FROM users'):
        user = {}
        user["id"] = row["id"]
        user["name"] = row["username"]
        user["privileges"] = 'Потребител' if row["privileges"] == 0 else 'Админ'
        users.append(user)
    return users

def stats():
    stats = []
    for row in functions.query_db('SELECT * FROM sqlite_sequence'):
        temp = {}
        temp["name"] = row["name"]
        temp["count"] = row["seq"]
        stats.append(temp)
    return stats