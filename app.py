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


@app.route('/', methods=["GET", "POST"])
def render_homepage():
    if request.method == "POST" and is_logged_in():
        category = request.form['category'].strip().title()

        if len(category) > 20:
            return redirect("?error=Category+cannot+be+longer+than+20+characters.")
        else:
            # connect to the database
            con = create_connection(DB_NAME)

            query = "INSERT INTO categories (cat_id, category) " \
                "VALUES(NULL, ?)"

            cur = con.cursor()  # You need this line next
            try:
                cur.execute(query, (category, ))  # this line actually executes the query
            except:
                return redirect('/error=Unknown+error')

            con.commit()
            con.close()




    # connect to the database
    con = create_connection(DB_NAME)
    query = "SELECT cat_id, category FROM categories ORDER BY category ASC"
    cur = con.cursor()  # You need this line next
    cur.execute(query)  # this line actually executes the query
    category_list = cur.fetchall()  # puts the results into a list usable in python
    con.close()

    category_list = get_categories()
    return render_template('home.html', categories=category_list, logged_in=is_logged_in())


@app.route('/category/<cat_id>', methods=["GET", "POST"])
def render_category(cat_id):
    if request.method == "POST" and is_logged_in():
        maori = request.form['maori'].strip().lower()
        english = request.form['english'].strip().lower()
        definition = request.form['definition'].strip()
        word_level = request.form['word_level']
        date_added = request.form['date_added']

        if len(maori) > 20:
            return redirect("?error=Maori+word+cannot+be+longer+than+20+characters.")
        elif len(english) > 20:
            return redirect("?error=English+word+cannot+be+longer+than+20+characters.")
        elif len(definition) < 5:
            return redirect("?error=Definition+cannot+be+less+than+5+characters.")
        elif len(date_added) > 10:
            return redirect("?error=Date+cannot+be+longer+than+10+characters.")
        else:
            # connect to the database
            con = create_connection(DB_NAME)

            query = "INSERT INTO words " \
                    "(id, maori, english, cat_id, definition, word_level, user_id, image, date_added) " \
                    "VALUES(NULL, ?, ?, ?, ?, ?, ?, 'noimage.png', ?)"

            cur = con.cursor()  # You need this line next
            try:
                cur.execute(query, (maori, english, cat_id, definition, word_level, session['user_id'], date_added))  # this line actually executes the query
            except:
                return redirect('?error=Unknown+error')

            con.commit()
            con.close()



    # connect to the database
    con = create_connection(DB_NAME)
    query = "SELECT id, maori, english, cat_id, definition, word_level, user_id, image, date_added" \
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

    return render_template('category.html', words=word_list, categories=category_list,
                           cat_name_list=cat_name_list, logged_in=is_logged_in())


@app.route('/word/<id>')
def render_word(id):
    # connect to the database
    con = create_connection(DB_NAME)
    query = "SELECT id, maori, english, cat_id, definition, word_level, user_id, image, date_added" \
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

    query = "SELECT user_id, fname, lname " \
            "FROM users WHERE user_id=?"
    cur = con.cursor()  # You need this line next
    cur.execute(query, (word_list[0][6], ))  # this line actually executes the query
    user_name_list = cur.fetchall()  # puts the results into a list usable in python

    con.close()

    return render_template('word.html', words=word_list, categories=category_list,
                           cat_name_list=cat_name_list, logged_in=is_logged_in(),
                           user_name_list=user_name_list)


@app.route('/login', methods=["GET", "POST"])
def render_login_page():
    if is_logged_in():
        return redirect('/')
    print(request.form)
    if request.method == "POST":
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        query = """SELECT user_id, fname, lname, password FROM users WHERE email = ?"""
        con = create_connection(DB_NAME)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchall()
        con.close()
        # if given the email is not in the database this will raise an error
        # would be better to find out how to see if the query return an empty resultset
        try:
            user_id = user_data[0][0]
            fname = user_data[0][1]
            lname = user_data[0][2]
            db_password = user_data[0][3]
        except IndexError:
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        # check if the password is incorrect for that email address

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

        session['email'] = email
        session['user_id'] = user_id
        session['fname'] = fname
        session['lname'] = lname
        print('is logged in')
        print(session)
        return redirect('/')

    # connect to the database
    con = create_connection(DB_NAME)
    query = "SELECT cat_id, category FROM categories ORDER BY category ASC"
    cur = con.cursor()  # You need this line next
    cur.execute(query)  # this line actually executes the query
    category_list = cur.fetchall()  # puts the results into a list usable in python
    con.close()

    category_list = get_categories()

    return render_template('login.html', logged_in=is_logged_in(), categories=category_list)


@app.route('/signup', methods=['GET', 'POST'])
def render_signup_page():
    if is_logged_in():
        return redirect('/')

    if request.method == 'POST':
        print(request.form)
        fname = request.form.get('fname').strip().title()
        lname = request.form.get('lname').strip().title()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        password2 = request.form.get('password2')

        if password != password2:
            return redirect('/signup?error=Passwords+dont+match')

        if len(password) < 8:
            return redirect('/signup?error=Password+must+be+8+characters+or+more')

        hashed_password = bcrypt.generate_password_hash(password)

        con = create_connection(DB_NAME)

        query = "INSERT INTO users (user_id, fname, lname, email, password) " \
                "VALUES(NULL,?,?,?,?)"

        cur = con.cursor()  # You need this line next
        try:
            cur.execute(query, (fname, lname, email, hashed_password))  # this line actually executes the query
        except sqlite3.IntegrityError:
            return redirect('/signup?error=Email+is+already+used')

        con.commit()
        con.close()
        return redirect('/login')

    # connect to the database
    con = create_connection(DB_NAME)
    query = "SELECT cat_id, category FROM categories ORDER BY category ASC"
    cur = con.cursor()  # You need this line next
    cur.execute(query)  # this line actually executes the query
    category_list = cur.fetchall()  # puts the results into a list usable in python
    con.close()

    category_list = get_categories()

    return render_template('signup.html', logged_in=is_logged_in(), categories=category_list)


@app.route('/logout')
def logout():
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/?message=See+you+next+time!')


def is_logged_in():
    if session.get("email") is None:
        print("not logged in")
        return False
    else:
        print("logged in")
        return True


if __name__ == '__main__':
    app.run()
