from flask import Flask, render_template, request, session, redirect
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "aj777qwerty55ugly%^$##"

DB_NAME = "Dictionary.db"


def create_connection(db_file):
    """create a connection to the sqlite db"""
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)

    return None


def get_categories():
    con = create_connection(DB_NAME)
    query = "SELECT cat_id, category" \
            " FROM categories ORDER BY category ASC"
    cur = con.cursor()  # You need this line next
    cur.execute(query)  # this line actually executes the query
    category_list = cur.fetchall()  # puts the results into a list usable in python
    con.close()
    return category_list


@app.route('/')
def render_homepage():
    # connect to the database
    con = create_connection(DB_NAME)
    query = "SELECT cat_id, category FROM categories ORDER BY category ASC"
    cur = con.cursor()  # You need this line next
    cur.execute(query)  # this line actually executes the query
    category_list = cur.fetchall()  # puts the results into a list usable in python
    con.close()

    category_list = get_categories()
    return render_template('home.html', categories=category_list)


@app.route('/category/<cat_id>')
def render_category(cat_id):
    # connect to the database
    con = create_connection(DB_NAME)
    query = "SELECT id, maori, english, cat_id, definition, word_level, user_added, image, date_added" \
            " FROM words WHERE cat_id=? ORDER BY maori ASC"
    cur = con.cursor()  # You need this line next
    cur.execute(query, (cat_id, ))  # this line actually executes the query
    word_list = cur.fetchall()  # puts the results into a list usable in python

    # connect to the database
    con = create_connection(DB_NAME)
    query = "SELECT cat_id, category " \
            "FROM categories ORDER BY category ASC"
    cur = con.cursor()  # You need this line next
    cur.execute(query)  # this line actually executes the query
    category_list = cur.fetchall()  # puts the results into a list usable in python

    # connect to the database
    query = "SELECT cat_id, category " \
            "FROM categories WHERE cat_id=?"
    cur = con.cursor()  # You need this line next
    cur.execute(query, (word_list[0][3],))  # this line actually executes the query
    cat_name_list = cur.fetchall()  # puts the results into a list usable in python

    con.close()

    return render_template('category.html', words=word_list, categories=category_list, cat_name_list=cat_name_list)


@app.route('/word/<id>')
def render_word(id):
    # connect to the database
    con = create_connection(DB_NAME)
    query = "SELECT id, maori, english, cat_id, definition, word_level, user_added, image, date_added" \
            " FROM words WHERE id=? ORDER BY maori ASC"
    cur = con.cursor()  # You need this line next
    cur.execute(query, (id, ))  # this line actually executes the query
    word_list = cur.fetchall()  # puts the results into a list usable in python

    # connect to the database
    query = "SELECT cat_id, category " \
            "FROM categories ORDER BY category ASC"
    cur = con.cursor()  # You need this line next
    cur.execute(query)  # this line actually executes the query
    category_list = cur.fetchall()  # puts the results into a list usable in python

    # connect to the database
    query = "SELECT cat_id, category " \
            "FROM categories WHERE cat_id=?"
    cur = con.cursor()  # You need this line next
    cur.execute(query, (word_list[0][3], ))  # this line actually executes the query
    cat_name_list = cur.fetchall()  # puts the results into a list usable in python

    con.close()

    return render_template('word.html', words=word_list, categories=category_list, cat_name_list=cat_name_list)


if __name__ == '__main__':
    app.run()
