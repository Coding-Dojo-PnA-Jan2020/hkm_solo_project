from flask import Flask, render_template, redirect, request, flash, session
from mySQLConnection import connectToMySQL
import re
from flask_bcrypt import Bcrypt

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key='hakiem'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/registration', methods=['POST'])
def register():
    is_valid = True
    if len(request.form['fname']) < 2:
        is_valid = False
        flash("First name must be at least 2 characters long.")
    if len(request.form['lname']) < 2:
        is_valid = False
        flash("Last name must be at least 2 characters long.")
    if not EMAIL_REGEX.match(request.form['email']):
        flash('Invalid email address.')
    if len(request.form['pword']) < 8:
        is_valid = False
        flash("Password must be at least 8 characters long.")
    if request.form['pword'] != request.form['cpword']:
        is_valid = False
        flash("Passwords do not match.")
    
    mysql = connectToMySQL('culp')
    validate_email_query = 'SELECT id FROM users WHERE email = %(email)s;'
    form_data = {
        'email': request.form['email']
    }
    existing_users = mysql.query_db(validate_email_query, form_data)

    if existing_users:
        flash("Email address is already in use.")
        is_valid = False
    
    if not is_valid:
        return redirect('/')


    pw_hash = bcrypt.generate_password_hash(request.form['pword']) 
    mysql = connectToMySQL('culp')
    query = 'INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(fn)s, %(ln)s, %(em)s, %(pw)s, now(), now())'
    data = {
        'fn': request.form['fname'],
        'ln': request.form['lname'],
        'em': request.form['email'],
        'pw': pw_hash
    }

    user_id = mysql.query_db(query, data)
    session['user_id'] = user_id

    return redirect('/profile')

@app.route('/login', methods=['POST'])
def login():
    mysql = connectToMySQL('culp')
    valid_email = 'SELECT * FROM users WHERE users.email = %(email)s;'
    valid = {
        'email': request.form['email']
    }
    result = mysql.query_db(valid_email, valid)
    if result:
        hashed_password = result[0]['password']
        if bcrypt.check_password_hash(hashed_password, request.form['pword']):
            session['user_id'] = result[0]['id']
            return redirect('/profile')
    flash('You could not be logged in')
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect('/')

    mysql = connectToMySQL('culp')
    query = 'SELECT * FROM users WHERE users.id = %(id)s'
    data = {
        'id': session['user_id']
    }
    user = mysql.query_db(query, data)

    mysql = connectToMySQL('culp')
    query = 'SELECT goals.goals, goals.id, goals.user_id, users.first_name FROM goals JOIN users on goals.user_id = users.id'
    goals = mysql.query_db(query)

    return render_template('profile.html', users = user[0], goals=goals)

@app.route('/new_goals', methods=['POST'])
def new_goals():
    is_valid = True

    if 'user_id' not in session:
        return redirect('/')

    if len(request.form['new_goal']) < 5:
        is_valid = False
        flash("A new goal must be at least 5 characters long.")

    if is_valid:
        mysql = connectToMySQL('culp')
        query = 'INSERT INTO goals (goals, user_id, created_at, updated_at) VALUES (%(goal)s, %(id)s, now(), now())'
        data = {
            'goal': request.form['new_goal'],
            'id': session['user_id']
        }
        goals = mysql.query_db(query, data)
    return redirect('/profile')

@app.route("/goals/<goals_id>/delete")
def delete_goals(goals_id):
    
    query = 'DELETE FROM likes WHERE goals_id = %(goals_id)s'
    data = {
        'goals_id': goals_id
    }
    mysql = connectToMySQL('culp')
    mysql.query_db(query, data)
    
    query = "DELETE FROM goals WHERE id = %(goals_id)s"
    mysql = connectToMySQL('culp')
    mysql.query_db(query, data)
    return redirect("/profile")

@app.route('/habits')
def habits():
    if 'user_id' not in session:
        return redirect('/')

    mysql = connectToMySQL('culp')
    query = 'SELECT * FROM users WHERE users.id = %(id)s'
    data = {
        'id': session['user_id']
    }
    user = mysql.query_db(query, data)

    mysql = connectToMySQL('culp')
    query = 'SELECT habits.habit, habits.id, habits.user_id, users.first_name FROM habits JOIN users on habits.user_id = users.id'
    habits = mysql.query_db(query)

    return render_template('habits.html',users=user[0], habits=habits)

@app.route('/new_habits', methods=['POST'])
def new_habits():
    is_valid = True

    if 'user_id' not in session:
        return redirect('/')

    if len(request.form['new_habit']) < 5:
        is_valid = False
        flash("A new habit must be at least 5 characters long.")

    if is_valid:
        mysql = connectToMySQL('culp')
        query = 'INSERT INTO habits (habit, user_id, created_at, updated_at) VALUES (%(habit)s, %(id)s, now(), now())'
        data = {
            'habit': request.form['new_habit'],
            'id': session['user_id']
        }
        habits = mysql.query_db(query, data)
    return redirect('/habits')

@app.route("/habits/<habits_id>/delete")
def delete_habits(habits_id):
    
    query = "DELETE FROM habits WHERE id = %(habits_id)s"
    mysql = connectToMySQL('culp')
    mysql.query_db(query, data)
    return redirect("/habits")

@app.route('/motivation')
def motivation():
    if 'user_id' not in session:
        return redirect('/')

    mysql = connectToMySQL('culp')
    query = 'SELECT * FROM users WHERE users.id = %(id)s'
    data = {
        'id': session['user_id']
    }
    user = mysql.query_db(query, data)

    mysql = connectToMySQL('culp')
    query = 'SELECT motivation.motivation, motivation.id, motivation.user_id, users.first_name FROM motivation JOIN users on motivation.user_id = users.id'
    motivation = mysql.query_db(query)

    return render_template('motivation.html',users=user[0], motivation=motivation)

@app.route('/new_motivation', methods=['POST'])
def new_motivation():
    is_valid = True

    if 'user_id' not in session:
        return redirect('/')

    if len(request.form['new_motivation']) < 5:
        is_valid = False
        flash("A new motivational quote must be at least 5 characters long.")

    if is_valid:
        mysql = connectToMySQL('culp')
        query = 'INSERT INTO motivation (motivation, user_id, created_at, updated_at) VALUES (%(motivation)s, %(id)s, now(), now())'
        data = {
            'motivation': request.form['new_motivation'],
            'id': session['user_id']
        }
        motivation = mysql.query_db(query, data)
    return redirect('/motivation')

@app.route("/motivation/<motivation_id>/delete")
def delete_motivation(motivation_id):

    query = "DELETE FROM motivation WHERE id = %(motivation_id)s"
    data = {
        'motivation_id': motivation_id
    }
    mysql = connectToMySQL('culp')
    mysql.query_db(query, data)
    return redirect("/motivation")

if __name__ == '__main__':
    app.run(debug=True)