from flask import Flask, render_template, request, session, redirect
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

# imports all plugins needed


app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "aj777qwerty5@#$%^&*(OMG5ugly%^$##"

DB_NAME = "Dictionary.db"


def create_connection(db_file):
    # create a connection to the sqlite database
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)

    return None


def get_categories():
    # get categories from db and store them as category_list
    con = create_connection(DB_NAME)
    query = "SELECT cat_id, category" \
            " FROM categories ORDER BY category ASC"
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    con.close()
    return category_list


@app.route('/', methods=["GET", "POST"])
# home
def render_homepage():
    # input new category into db from form on homepage
    if request.method == "POST" and is_logged_in():
        category = request.form['category'].strip().title()  # gets input from form

        if len(category) > 20:  # data validation
            return redirect("?error=Category+cannot+be+longer+than+20+characters.")
        else:  # if form inputs are good then upload it
            con = create_connection(DB_NAME)  # connect to db

            query = "INSERT INTO categories (cat_id, category) " \
                    "VALUES(NULL, ?)"

            cur = con.cursor()
            try:
                cur.execute(query, (category,))  # executes the query into db
            except sqlite3.Error:
                return redirect('/error=Unknown+error')  # in case of an expected error

            con.commit()
            con.close()

    return render_template('home.html', categories=get_categories(), logged_in=is_logged_in())


@app.route('/category/<cat_id>', methods=["GET", "POST"])
# specific category
def render_category(cat_id):
    # uploading word form to database
    if request.method == "POST" and is_logged_in():
        # get data from form
        maori = request.form['maori'].strip().lower()
        english = request.form['english'].strip().lower()
        definition = request.form['definition'].strip()
        word_level = request.form['word_level']
        date_added = request.form['date_added']

        # data validation
        if len(maori) > 20:
            return redirect("?error=Maori+word+cannot+be+longer+than+20+characters.")
        elif len(english) > 20:
            return redirect("?error=English+word+cannot+be+longer+than+20+characters.")
        elif len(definition) < 5:
            return redirect("?error=Definition+cannot+be+less+than+5+characters.")
        elif len(date_added) > 10:
            return redirect("?error=Date+cannot+be+longer+than+10+characters.")
        else:
            # if data is good then connect to db and upload it
            con = create_connection(DB_NAME)

            query = "INSERT INTO words " \
                    "(word_id, maori, english, cat_id, definition, word_level, user_id, image, date_added) " \
                    "VALUES(NULL, ?, ?, ?, ?, ?, ?, 'noimage.png', ?)"

            cur = con.cursor()
            try:  # try to execute query
                cur.execute(query, (maori, english, cat_id, definition, word_level, session['user_id'], date_added))
            except sqlite3.Error:  # catch unexpected errors
                return redirect('?error=Unknown+error')

            con.commit()
            con.close()

    con = create_connection(DB_NAME)
    # connect to the database to select words in specific category
    query = "SELECT word_id, maori, english, cat_id, definition, word_level, user_id, image, date_added" \
            " FROM words WHERE cat_id=? ORDER BY maori ASC"
    cur = con.cursor()
    cur.execute(query, (cat_id,))  # execute query
    word_list = cur.fetchall()  # puts results into list

    # connect to the database to select only the selected category
    query = "SELECT cat_id, category " \
            "FROM categories WHERE cat_id=?"
    cur = con.cursor()
    cur.execute(query, (cat_id,))  # execute query
    cat_name_list = cur.fetchall()  # puts results into list

    con.close()

    return render_template('category.html', words=word_list, categories=get_categories(),
                           cat_name_list=cat_name_list, logged_in=is_logged_in())


@app.route('/word/<word_id>', methods=["GET", "POST"])
# specific word
def render_word(word_id):
    # delete current word
    if request.method == "POST" and is_logged_in():
        email = request.form['email']  # gets input from form

        if email != session['email']:  # data validation
            return redirect("?error=Email+is+incorrect.")
        else:  # if email is correct then delete word
            return redirect('/confirmdeleteword/{}'.format(word_id))

    # connect to the database to select information on selected word
    con = create_connection(DB_NAME)
    query = "SELECT word_id, maori, english, cat_id, definition, word_level, user_id, image, date_added" \
            " FROM words WHERE word_id=? ORDER BY maori ASC"
    cur = con.cursor()
    cur.execute(query, (word_id,))  # execute query
    word_list = cur.fetchall()  # put results in list

    # connect to the database to select category name of selected word
    query = "SELECT cat_id, category " \
            "FROM categories WHERE cat_id=?"
    cur = con.cursor()
    cur.execute(query, (word_list[0][3],))  # execute query
    cat_name_list = cur.fetchall()  # put results in list

    # connect to the database to select the users details that added selected work
    query = "SELECT user_id, fname, lname " \
            "FROM users WHERE user_id=?"
    cur = con.cursor()
    cur.execute(query, (word_list[0][6],))  # execute query
    user_name_list = cur.fetchall()  # put results in list

    con.close()

    return render_template('word.html', words=word_list, categories=get_categories(),
                           cat_name_list=cat_name_list, logged_in=is_logged_in(),
                           user_name_list=user_name_list)


@app.route('/confirmdeleteword/<word_id>', methods=["GET", "POST"])
# delete word
def render_confirmdeleteword_page(word_id):
    if request.method == "POST" and is_logged_in():
        con = create_connection(DB_NAME)  # connect to db

        query = "DELETE FROM words WHERE word_id=?"

        cur = con.cursor()
        try:
            cur.execute(query, (word_id,))  # executes the query
        except sqlite3.Error:
            return redirect('/error=Unknown+error')  # in case of an expected error

        con.commit()
        con.close()
        return redirect('/?message=Word+successfully+deleted')  # return home

    # connect to the database to select information on selected word
    con = create_connection(DB_NAME)
    query = "SELECT word_id, maori, english, cat_id, definition, word_level, user_id, image, date_added" \
            " FROM words WHERE word_id=? ORDER BY maori ASC"
    cur = con.cursor()
    cur.execute(query, (word_id,))  # execute query
    word_list = cur.fetchall()  # put results in list

    # connect to the database to select the users details that added selected work
    query = "SELECT user_id, fname, lname " \
            "FROM users WHERE user_id=?"
    cur = con.cursor()
    cur.execute(query, (word_list[0][6],))  # execute query
    user_name_list = cur.fetchall()  # put results in list

    con.close()

    return render_template('confirmdeleteword.html', words=word_list, categories=get_categories(),
                           logged_in=is_logged_in(), user_name_list=user_name_list)


@app.route('/login', methods=["GET", "POST"])
# login
def render_login_page():
    if is_logged_in():
        return redirect('/?message=You+are+already+logged+in')  # if already logged in re-direct to home
    print(request.form)

    # logging in
    if request.method == "POST":
        # get details from form
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        # get details from db
        query = """SELECT user_id, fname, lname, password FROM users WHERE email = ?"""
        con = create_connection(DB_NAME)
        cur = con.cursor()
        cur.execute(query, (email,))  # execute query
        user_data = cur.fetchall()  # put into list
        con.close()
        # data validation: is email and password correct
        try:
            user_id = user_data[0][0]
            fname = user_data[0][1]
            lname = user_data[0][2]
            db_password = user_data[0][3]
        except IndexError:  # email or password doesn't match up to db then pass through
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        # checking if the password is incorrect for that email address

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

        # if all correct then add details to session
        session['email'] = email
        session['user_id'] = user_id
        session['fname'] = fname
        session['lname'] = lname
        print('is logged in')
        print(session)
        return redirect('/')

    return render_template('login.html', logged_in=is_logged_in(), categories=get_categories())


@app.route('/signup', methods=['GET', 'POST'])
# sign up
def render_signup_page():
    if is_logged_in():  # if already logged in then go home
        return redirect('/You+are+already+logged+in')

    if request.method == 'POST':
        print(request.form)
        # get info from form
        fname = request.form.get('fname').strip().title()
        lname = request.form.get('lname').strip().title()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        password2 = request.form.get('password2')

        if password != password2:  # password confirmation
            return redirect('/signup?error=Passwords+dont+match')

        if len(password) < 8:  # data validation
            return redirect('/signup?error=Password+must+be+8+characters+or+more')

        hashed_password = bcrypt.generate_password_hash(password)  # hash the password (encrypt

        con = create_connection(DB_NAME)

        # add user to database
        query = "INSERT INTO users (user_id, fname, lname, email, password) " \
                "VALUES(NULL,?,?,?,?)"

        cur = con.cursor()
        try:
            cur.execute(query, (fname, lname, email, hashed_password))  # execute query
        except sqlite3.IntegrityError:  # in case of unexpected error
            return redirect('/signup?error=Email+is+already+used')

        con.commit()
        con.close()
        return redirect('/login?message=Successfully+created+an+account.+Please+sign+in+to+continue')

    return render_template('signup.html', logged_in=is_logged_in(), categories=get_categories())


@app.route('/logout')
# log out
def logout():
    # deletes session in order to log out
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/?message=See+you+next+time!')


def is_logged_in():
    # check if logged in by checking if session email is empty or not
    if session.get("email") is None:
        print("not logged in")
        return False
    else:  # if email isn't empty then user must be logged in
        print("logged in")
        return True


if __name__ == '__main__':
    app.run()
