from flask import Flask, flash, render_template, request, session, redirect
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt
# imports everything needed

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "aj777qwerty5@#$%^&*(OMG5ugly%^$##"

DB_NAME = "Dictionary.db"


def create_connection(db_file):
    # create a connection to the sqlite database
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:  # unless there's an error
        print(e)
    return None


def get_categories():
    # get categories from db and store them as category_list
    # this function will be called on every page
    con = create_connection(DB_NAME)
    query = """SELECT cat_id, category 
            FROM categories 
            ORDER BY category"""
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    con.close()

    return category_list


@app.route('/', methods=["GET", "POST"])
# home
def render_homepage():
    # from form on homepage
    # input new category into db from form
    if request.method == "POST" and is_logged_in():  # has to be logged in
        category = request.form['category'].strip().title()  # gets input from form and cleans data

        if len(category) > 20:  # data validation
            flash('Category cannot be longer than 20 characters')
            return redirect(request.referrer)

        else:  # if form inputs are good then upload it
            con = create_connection(DB_NAME)  # connect to db
            query = """INSERT INTO categories (cat_id, category) 
                    VALUES(NULL, ?)"""
            cur = con.cursor()

            try:
                cur.execute(query, (category,))  # executes the query into db

            except sqlite3.Error:
                flash('Unknown error')
                return redirect(request.referrer)  # in case of an expected error

            con.commit()
            con.close()

    return render_template('home.html', categories=get_categories(), logged_in=is_logged_in())


@app.route('/search', methods=["GET", "POST"])
# search
def render_search():
    default_search = request.args.get('search')

    if default_search == 'Searching All Words...':
        default_search = None

    # from form on search page
    # searching database for query
    if request.method == "POST":
        # get data from form and clean it
        search_query = request.form['search_query'].strip()

        # search validation
        if len(search_query) > 20:
            flash('Search query cannot be longer than 20 characters')
            return redirect(request.referrer)

        elif len(search_query) == 0:
            return redirect('/searchresults/Searching%20All%20Words...')

        elif ' ' in search_query:
            flash('Search query can not contain a space!')
            return redirect(request.referrer)

        else:  # if search query clean then search it
            return redirect('/searchresults/{}'.format(search_query))

    return render_template('search.html', categories=get_categories(),
                           logged_in=is_logged_in(), default_search=default_search)


@app.route('/searchresults/', defaults={'search_query': 'Searching All Words...'}, methods=["GET", "POST"])
@app.route('/searchresults/<search_query>', methods=["GET", "POST"])
# search results
def render_searchresults(search_query):

    search_filter = 'maori_filter'  # set default filter as maori filter

    if request.method == "POST":
        # get data from filter form
        search_filter = request.form['search_filter']

    if search_filter == 'english_filter':
        filter_order = 'english, maori'
    elif search_filter == 'word_level_filter':
        filter_order = 'word_level, maori'
    elif search_filter == 'recent_filter':
        filter_order = 'word_id DESC'
    elif search_filter == 'maori_filter':
        filter_order = 'maori, english'
    else:
        filter_order = 'maori, english'

    con = create_connection(DB_NAME)  # connect to db
    # have to use .format() to put placeholders in wildcards

    query = """SELECT word_id, maori, english, word_level FROM words 
                WHERE maori LIKE '%{0}%' 
                OR english LIKE '%{0}%' 
                OR definition LIKE '%{0}%'
                OR word_level LIKE '%{0}%'
                ORDER BY {1}""".format(search_query, filter_order)

    if search_query == 'Searching All Words...':
        query = """SELECT word_id, maori, english, word_level FROM words
                ORDER BY {}""".format(filter_order)

    cur = con.cursor()

    try:
        cur.execute(query)  # executes the query into db

    except sqlite3.Error:
        flash('Unknown Error')
        return redirect(request.referrer)  # in case of an expected error

    search_results = cur.fetchall()
    con.commit()
    con.close()

    return render_template('searchresults.html', categories=get_categories(),
                           logged_in=is_logged_in(), search_results=search_results,
                           search_query=search_query, search_filter=search_filter)


@app.route('/category/<cat_id>', methods=["GET", "POST"])
# category
def render_category(cat_id):
    search_filter = 'maori_filter'  # set default filter as maori filter

    if request.method == "POST":
        # get data from filter form
        search_filter = request.form['search_filter']

    con = create_connection(DB_NAME)  # connect to db
    # have to use .format() to put placeholders in wildcards

    if search_filter == 'english_filter':
        query = """SELECT word_id, maori, english, cat_id, definition, word_level, user_id, image, date_added 
                    FROM words WHERE cat_id=? ORDER BY english, maori"""
    elif search_filter == 'word_level_filter':
        query = """SELECT word_id, maori, english, cat_id, definition, word_level, user_id, image, date_added 
                    FROM words WHERE cat_id=? ORDER BY word_level, maori"""
    elif search_filter == 'recent_filter':
        query = """SELECT word_id, maori, english, cat_id, definition, word_level, user_id, image, date_added 
                    FROM words WHERE cat_id=? ORDER BY word_id DESC"""
    else:
        query = """SELECT word_id, maori, english, cat_id, definition, word_level, user_id, image, date_added 
                    FROM words WHERE cat_id=? ORDER BY maori, english"""

    cur = con.cursor()

    cur.execute(query, (cat_id,))  # execute query
    word_list = cur.fetchall()  # puts results into list

    # connect to the database to select the selected category
    query = """SELECT cat_id, category 
            FROM categories WHERE cat_id=?"""
    cur = con.cursor()
    cur.execute(query, (cat_id,))  # execute query
    cat_name_list = cur.fetchall()  # puts results into list

    if len(cat_name_list) == 0:
        flash('Unknown Category')
        return redirect('/')

    con.close()

    return render_template('category.html', words=word_list, categories=get_categories(),
                           cat_name_list=cat_name_list, logged_in=is_logged_in(), search_filter=search_filter)


@app.route('/addword/<cat_id>', methods=["GET", "POST"])
# add word
def render_addword(cat_id):
    # form from category page
    # uploading the new word from the form to database
    if request.method == "POST" and is_logged_in():
        # get data from form and clean data
        maori = request.form['maori'].strip().lower()
        english = request.form['english'].strip().lower()
        definition = request.form['definition'].strip()
        word_level = request.form['word_level']

        # data validation
        if len(maori) > 20:
            flash('Maori word cannot be longer than 20 characters')
            return redirect(request.referrer)
        elif len(english) > 20:
            flash('English word cannot be longer than 20 characters')
            return redirect(request.referrer)
        elif not 5 < len(definition) < 100:
            flash('Definition must be between 5 and 100 characters')
            return redirect(request.referrer)
        else:
            # if data is good then connect to db and upload it
            con = create_connection(DB_NAME)
            query = """INSERT INTO words
                    (word_id, maori, english, cat_id, definition, word_level, user_id, image, date_added)
                    VALUES(NULL, ?, ?, ?, ?, ?, ?, 'noimage.png', strftime('%d-%m-%Y','now'))"""
            cur = con.cursor()

            try:  # try to execute query
                cur.execute(query, (maori, english, cat_id, definition, word_level, session['user_id']))

            except sqlite3.Error:  # catch unexpected errors
                flash('Unknown Error')
                return redirect(request.referrer)

            con.commit()
            con.close()
            flash('Successfully added word')
            return redirect('/category/{}'.format(cat_id))

    con = create_connection(DB_NAME)
    # connect to the database to select the selected category
    query = """SELECT cat_id, category 
            FROM categories WHERE cat_id=?"""
    cur = con.cursor()
    cur.execute(query, (cat_id, ))  # execute query
    cat_name_list = cur.fetchall()  # puts results into list

    if len(cat_name_list) == 0:
        flash('Unknown Category')
        return redirect('/')

    con.close()

    return render_template('addword.html', categories=get_categories(),
                           cat_name_list=cat_name_list, logged_in=is_logged_in())


@app.route('/editcategory/<cat_id>', methods=["GET", "POST"])
# edit category
def render_editcategory_page(cat_id):
    if request.method == "POST" and is_logged_in():
        # form from edit category page to edit word
        # get data from form and clean
        category = request.form['category'].strip().title()

        # data validation
        if len(category) > 20:
            flash('Category name cannot be longer than 20 characters')
            return redirect(request.referrer)

        else:
            con = create_connection(DB_NAME)
            query = """UPDATE categories 
                    SET category = ? 
                    WHERE cat_id = ?"""
            cur = con.cursor()

            try:  # try to execute query
                cur.execute(query, (category, cat_id))

            except sqlite3.Error:  # catch unexpected errors
                flash('Unknown error')
                return redirect(request.referrer)

            con.commit()
            con.close()
            flash('Successfully edited category')
            return redirect('/category/{}'.format(cat_id))

    # connect to the database to select information on selected category
    con = create_connection(DB_NAME)
    query = """SELECT cat_id, category 
            FROM categories WHERE cat_id=?"""
    cur = con.cursor()
    cur.execute(query, (cat_id,))  # execute query
    cat_name_list = cur.fetchall()  # put results in list

    if len(cat_name_list) == 0:
        flash('Unknown Category')
        return redirect('/')

    con.close()

    return render_template('editcategory.html', cat_name_list=cat_name_list, categories=get_categories(),
                           logged_in=is_logged_in())


@app.route('/confirmdeletecategory/<cat_id>', methods=["GET", "POST"])
# delete category
def render_confirmdeletecatgeory_page(cat_id):
    if request.method == "POST" and is_logged_in():

        con = create_connection(DB_NAME)  # connect to db

        query = "DELETE FROM categories WHERE cat_id=?"
        cur = con.cursor()

        try:
            cur.execute(query, (cat_id,))  # executes the query

        except sqlite3.Error:
            flash('Unknown error')
            return redirect(request.referrer)  # in case of an expected error

        con.commit()
        con.close()

        if request.form['submit'] == 'DELETE CATEGORY':
            print('delete category')
            flash('Category Successfully deleted')
            return redirect('/')  # return home
        elif request.form['submit'] == 'DELETE CATEGORY AND ALL WORDS WITHIN':
            print('delete category and words')

            con = create_connection(DB_NAME)

            query = "DELETE FROM words WHERE cat_id=?"
            cur = con.cursor()

            try:
                cur.execute(query, (cat_id,))  # executes the query

            except sqlite3.Error:
                flash('Unknown error')
                return redirect(request.referrer)  # in case of an expected

            con.commit()
            con.close()

            flash('Successfully deleted category and all words within')
            return redirect('/')
        else:
            print('error')
            flash('There was an error. Please try again later.')
            return redirect('/')

    # connect to the database to select information on selected category
    con = create_connection(DB_NAME)
    query = """SELECT cat_id, category
            FROM categories WHERE cat_id=?"""
    cur = con.cursor()
    cur.execute(query, (cat_id,))  # execute query
    cat_name_list = cur.fetchall()  # put results in list

    if len(cat_name_list) == 0:
        flash('Unknown Category')
        return redirect('/')

    query = """SELECT word_id, cat_id
        FROM words
        WHERE cat_id=?"""
    cur = con.cursor()
    cur.execute(query, (cat_id,))
    words_number = cur.fetchall()

    print(words_number)

    con.close()

    return render_template('confirmdeletecategory.html', categories=get_categories(),
                           logged_in=is_logged_in(), cat_name_list=cat_name_list,
                           words_number=words_number)


@app.route('/word/<word_id>')
# word page
def render_word(word_id):
    # connect to the database to select information on selected word
    con = create_connection(DB_NAME)
    query = """SELECT word_id, maori, english, cat_id, definition, word_level, user_id, image, date_added 
            FROM words WHERE word_id=? ORDER BY maori"""
    cur = con.cursor()
    cur.execute(query, (word_id,))  # execute query
    word_list = cur.fetchall()  # put results in list

    if len(word_list) == 0:
        flash('Unknown Word')
        return redirect('/')

    # connect to the database to select category name of selected word
    query = """SELECT cat_id, category 
            FROM categories WHERE cat_id=?"""
    cur = con.cursor()
    cur.execute(query, (word_list[0][3],))  # execute query
    cat_name_list = cur.fetchall()  # put results in list

    # connect to the database to select the users details that added selected work
    query = """SELECT user_id, fname, lname 
            FROM users WHERE user_id=?"""
    cur = con.cursor()
    cur.execute(query, (word_list[0][6],))  # execute query
    user_name_list = cur.fetchall()  # put results in list

    con.close()

    return render_template('word.html', words=word_list, categories=get_categories(),
                           cat_name_list=cat_name_list, logged_in=is_logged_in(),
                           user_name_list=user_name_list)


@app.route('/editword/<word_id>', methods=["GET", "POST"])
# edit word
def render_editword_page(word_id):
    if request.method == "POST" and is_logged_in():
        # form from page
        # get all data from form and clean
        maori = request.form['maori'].strip().lower()
        english = request.form['english'].strip().lower()
        cat = request.form['cat']
        definition = request.form['definition'].strip()
        word_level = request.form['word_level']
        image = request.form['image']

        # data validation
        if len(maori) > 20:
            flash('Maori word cannot be longer than 20 characters')
            return redirect(request.referrer)
        elif len(english) > 20:
            flash('English word cannot be longer than 20 characters')
            return redirect(request.referrer)
        elif not 5 < len(definition) < 100:
            flash('Definition must be between 5 and 100 characters')
            return redirect(request.referrer)
        else:
            con = create_connection(DB_NAME)

            query = """SELECT cat_id, category
            FROM categories
            WHERE category=?"""
            cur = con.cursor()
            cur.execute(query, (cat,))
            cat_id = cur.fetchall()[0][0]

            query = """UPDATE words 
                    SET maori = ?, english = ?, cat_id = ?, definition = ?, 
                    word_level = ?, user_id=?, image = ?, date_added = strftime('%d-%m-%Y','now') 
                    WHERE word_id=?"""
            cur = con.cursor()

            try:  # try to execute query
                cur.execute(query, (maori, english, cat_id, definition, word_level, session['user_id'], image, word_id))

            except sqlite3.Error:  # catch unexpected errors
                flash('Unknown error')
                return redirect(request.referrer)

            con.commit()
            con.close()
            flash('Successfully edited word')
            return redirect('/word/{}'.format(word_id))

    # connect to the database to select information on selected word
    con = create_connection(DB_NAME)
    query = """SELECT word_id, maori, english, cat_id, definition, word_level, image 
            FROM words WHERE word_id=? ORDER BY maori"""
    cur = con.cursor()
    cur.execute(query, (word_id,))  # execute query
    word_list = cur.fetchall()  # put results in list

    if len(word_list) == 0:
        flash('Unknown Word')
        return redirect('/')

    query = """SELECT cat_id, category
    FROM categories 
    ORDER BY category"""
    cur = con.cursor()
    cur.execute(query)  # execute query
    cat_list = cur.fetchall()  # put results in list

    con.close()

    return render_template('editword.html', words=word_list, categories=get_categories(),
                           logged_in=is_logged_in(), cat_list=cat_list)


@app.route('/confirmdeleteword/<word_id>', methods=["GET", "POST"])
# delete word
def render_confirmdeleteword_page(word_id):
    if request.method == "POST" and is_logged_in():
        # form to confirm deletion of word
        con = create_connection(DB_NAME)  # connect to db
        query = "DELETE FROM words WHERE word_id=?"
        cur = con.cursor()

        try:
            cur.execute(query, (word_id,))  # executes the query

        except sqlite3.Error:
            flash('Unknown error')
            return redirect(request.referrer)  # in case of an expected error

        con.commit()
        con.close()
        flash('Word Successfully deleted')
        return redirect('/')  # return home

    # connect to the database to select information on selected word
    con = create_connection(DB_NAME)
    query = """SELECT word_id, maori, english, cat_id, definition, word_level, user_id, image, date_added
            FROM words WHERE word_id=? ORDER BY maori"""
    cur = con.cursor()
    cur.execute(query, (word_id,))  # execute query
    word_list = cur.fetchall()  # put results in list

    if len(word_list) == 0:
        flash('Unknown Word')
        return redirect('/')

    # connect to the database to select the users details that added selected work
    query = """SELECT user_id, fname, lname
            FROM users WHERE user_id=?"""
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
        flash('You are already logged in')
        return redirect('/')  # if already logged in re-direct to home
    print(request.form)

    # log in form
    if request.method == "POST":
        # get details from form and clean
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
            flash('Email or password incorrect')
            return redirect(request.referrer)

        # checking if the password is incorrect for that email address

        if not bcrypt.check_password_hash(db_password, password):
            flash('Email or password incorrect')
            return redirect(request.referrer)

        # if all correct then add details to session
        session['email'] = email
        session['user_id'] = user_id
        session['fname'] = fname
        session['lname'] = lname
        print('is logged in')
        print(session)
        flash('Successfully Logged In')
        return redirect('/')

    return render_template('login.html', logged_in=is_logged_in(), categories=get_categories())


@app.route('/forgotpassword', methods=['GET', 'POST'])
# sign up
def render_forgotpassword_page():
    if is_logged_in():  # if already logged in then go home
        flash('You are already logged in')
        return redirect('/')

    # sign up form
    if request.method == 'POST':
        print(request.form)
        # get info from form and clean it
        fname = request.form.get('fname').strip().title()
        lname = request.form.get('lname').strip().title()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        password2 = request.form.get('password2')

        query = """SELECT user_id, fname, lname, email, password FROM users WHERE email = ?"""
        con = create_connection(DB_NAME)
        cur = con.cursor()
        try:
            cur.execute(query, (email,))  # execute query
            user_data = cur.fetchall()  # put into list
        except ValueError:
            flash('email is incorrect')
            return redirect(request.referrer)
        con.close()

        if len(user_data) == 0:
            flash('Email is incorrect')
            return redirect(request.referrer)

        elif password != password2:  # password confirmation
            flash('Passwords dont match')
            return redirect(request.referrer)

        # data validation
        elif len(password) < 8 or len(password) > 30:
            flash('Password must be between 8 and 30 characters')
            return redirect(request.referrer)

        elif fname != user_data[0][1]:
            flash('First name is incorrect')
            return redirect(request.referrer)

        elif lname != user_data[0][2]:
            flash('Last name is incorrect')
            return redirect(request.referrer)

        else:
            hashed_password = bcrypt.generate_password_hash(password)  # hash the password

            con = create_connection(DB_NAME)
            # add user to database
            query = """UPDATE users 
                    SET password=?
                    WHERE email=?"""
            cur = con.cursor()

            try:
                cur.execute(query, (hashed_password, email,))  # execute query

            except sqlite3.IntegrityError:  # in case of unexpected error
                flash('Unknown Error')
                return redirect(request.referrer)

            con.commit()
            con.close()
            flash('Successfully changed password. Please sign in to continue')
            return redirect('/login')

    return render_template('forgotpassword.html', logged_in=is_logged_in(), categories=get_categories())


@app.route('/signup', methods=['GET', 'POST'])
# sign up
def render_signup_page():
    if is_logged_in():  # if already logged in then go home
        flash('You cannot create an account if already signed in.')
        return redirect('/')

    # sign up form
    if request.method == 'POST':
        print(request.form)
        # get info from form and clean it
        fname = request.form.get('fname').strip().title()
        lname = request.form.get('lname').strip().title()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        password2 = request.form.get('password2')

        if password != password2:  # password confirmation
            flash('Passwords dont match')
            return redirect(request.referrer)

        # data validation
        elif len(password) < 8 or len(password) > 30:
            flash('Password must be between 8 and 30 characters')
            return redirect(request.referrer)

        elif len(fname) > 20:
            flash('First name cannot be greater than 20 characters')
            return redirect(request.referrer)

        elif len(lname) > 30:
            flash('Last name cannot be greater than 30 characters')
            return redirect(request.referrer)

        elif len(email) > 50:
            flash('Email cannot be greater than 50 characters')
            return redirect(request.referrer)

        else:
            con = create_connection(DB_NAME)
            query = """SELECT user_id, email
                        FROM users WHERE email=?"""
            cur = con.cursor()
            cur.execute(query, (email,))  # execute query
            email_check = cur.fetchall()  # put results in list

            if len(email_check) != 0:
                flash('Email already being used')
                return redirect(request.referrer)

            hashed_password = bcrypt.generate_password_hash(password)  # hash the password

            # add user to database
            query = "INSERT INTO users (user_id, fname, lname, email, password) " \
                    "VALUES(NULL,?,?,?,?)"
            cur = con.cursor()

            try:
                cur.execute(query, (fname, lname, email, hashed_password))  # execute query

            except sqlite3.IntegrityError:  # in case of unexpected error
                flash('Unknown Error')
                return redirect(request.referrer)

            con.commit()
            con.close()
            flash('Successfully created an account. Please sign in to continue')
            return redirect('/login')

    return render_template('signup.html', logged_in=is_logged_in(), categories=get_categories())


@app.route('/logout')
# log out
def logout():
    # delete session therefore function is_logged_in() will return None
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    flash('See you next time')
    return redirect('/')


def is_logged_in():
    # check if logged in by checking if session email is empty or not
    if session.get("email") is None:
        print("not logged in")
        return False
    else:  # if email isn't empty then user must be logged in
        print("logged in")
        return True


@app.route('/user')
# user account
def render_user_page():
    if not is_logged_in():  # redirects home if not logged in
        flash('You are not logged in')
        return redirect('/')

    con = create_connection(DB_NAME)

    # selects user info
    query = """SELECT user_id, fname, lname, email
    FROM users
    WHERE user_id=?"""
    cur = con.cursor()
    cur.execute(query, (session['user_id'],))
    user_info = cur.fetchall()

    # selects words that have been added by the user
    query = """SELECT word_id, maori, english, user_id, date_added
    FROM words
    WHERE user_id=?
    ORDER BY date_added"""
    cur = con.cursor()
    cur.execute(query, (session['user_id'],))
    user_words_info = cur.fetchall()

    con.close()

    return render_template('user.html', categories=get_categories(),
                           logged_in=is_logged_in(), user_info=user_info,
                           user_words_info=user_words_info)


@app.route('/publicuser/<user_id>')
# user public account
def render_userpublic_page(user_id):

    con = create_connection(DB_NAME)

    # selects user info
    query = """SELECT user_id, fname, lname, email
    FROM users
    WHERE user_id=?"""
    cur = con.cursor()
    cur.execute(query, (user_id,))
    user_info = cur.fetchall()

    # selects words that have been added by the user
    query = """SELECT word_id, maori, english, user_id, date_added
    FROM words
    WHERE user_id=?
    ORDER BY date_added"""
    cur = con.cursor()
    cur.execute(query, (user_id,))
    user_words_info = cur.fetchall()

    con.close()

    if len(user_info) == 0:
        flash('User does not exist')
        return redirect('/')

    return render_template('publicuser.html', categories=get_categories(),
                           logged_in=is_logged_in(), user_info=user_info,
                           user_words_info=user_words_info)


@app.route('/usersettings', methods=['GET', 'POST'])
# user settings
def render_usersettings_page():
    if not is_logged_in():  # if not logged in redirect
        flash('You are not logged in')
        return redirect('/')

    con = create_connection(DB_NAME)
    # get user info
    query = """SELECT user_id, fname, lname, email, password
        FROM users
        WHERE user_id=?"""
    cur = con.cursor()
    cur.execute(query, (session['user_id'],))
    user_info = cur.fetchall()

    con.close()

    if request.method == 'POST':
        print(request.form)
        # get info from form and clean it
        fname = request.form.get('fname').strip().title()
        lname = request.form.get('lname').strip().title()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        db_password = user_info[0][4]

        # data validation
        if len(fname) > 20:
            flash('First name cannot be greater than 20 characters')
            return redirect(request.referrer)

        elif len(lname) > 30:
            flash('Last name cannot be greater than 30 characters')
            return redirect(request.referrer)

        elif len(email) > 50:
            flash('Email cannot be greater than 50 characters')
            return redirect(request.referrer)

        # check if password is correct
        elif not bcrypt.check_password_hash(db_password, password):
            flash('Password incorrect')
            return redirect(request.referrer)

        else:  # if good then update
            con = create_connection(DB_NAME)

            query = """SELECT user_id, email
            FROM users WHERE email=?"""
            cur = con.cursor()
            cur.execute(query, (email,))
            email_check = cur.fetchall()

            if len(email_check) != 0 and email != session['email']:
                flash('Email already used')
                return redirect(request.referrer)

            query = """UPDATE users 
            SET fname = ?, lname = ?, email = ? 
            WHERE user_id=?"""
            cur = con.cursor()

            try:  # try to execute query
                cur.execute(query, (fname, lname, email, user_info[0][0]))

            except sqlite3.Error:  # catch unexpected errors
                flash('Unknown error')
                return redirect(request.referrer)

            con.commit()
            con.close()
            flash('Successfully edited details')
            return redirect('/user')

    return render_template('usersettings.html', categories=get_categories(),
                           logged_in=is_logged_in(), user_info=user_info)


@app.route('/changepassword', methods=['GET', 'POST'])
# password change
def render_changepassword_page():
    # if isn't logged in then redirect user
    if not is_logged_in():
        flash('You are not logged in')
        return redirect('/')

    con = create_connection(DB_NAME)
    # get user details
    query = """SELECT user_id, fname, lname, email, password
        FROM users
        WHERE user_id=?"""
    cur = con.cursor()
    cur.execute(query, (session['user_id'],))
    user_info = cur.fetchall()

    con.close()

    if request.method == 'POST':
        print(request.form)
        # get info from form and clean it
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        con_new_password = request.form.get('con_new_password')
        db_password = user_info[0][4]

        # data validation
        if new_password != con_new_password:
            flash('New passwords do not match')
            return redirect(request.referrer)

        elif len(new_password) > 20:
            flash('Password cannot be greater than 30 characters')
            return redirect(request.referrer)

        # check if password is correct
        elif not bcrypt.check_password_hash(db_password, current_password):
            flash('Current password is incorrect')
            return redirect(request.referrer)

        else:
            hashed_password = bcrypt.generate_password_hash(new_password)  # hash the password
            # if everything good then change password
            con = create_connection(DB_NAME)
            query = """UPDATE users 
            SET password = ?
            WHERE user_id=?"""
            cur = con.cursor()

            try:  # try to execute query
                cur.execute(query, (hashed_password, user_info[0][0]))

            except sqlite3.Error:  # catch unexpected errors
                flash('Unknown error')
                return redirect(request.referrer)

            con.commit()
            con.close()
            flash('Successfully updated password')
            return redirect('/user')

    return render_template('changepassword.html', categories=get_categories(),
                           logged_in=is_logged_in(), user_info=user_info)


@app.errorhandler(404)
# 404 page
def page_not_found(e):
    return render_template('404.html', e=e, categories=get_categories(), logged_in=is_logged_in())


if __name__ == '__main__':
    app.run()
