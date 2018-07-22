from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

Articles = Articles()

app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '1234'
app.config['MYSQL_DB'] = 'blog'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MYSQL

mysql = MySQL(app)

@app.route('/')
def index():
	return render_template('Home.html')

#About

@app.route('/About')
def About():
	return render_template('About.html')

#Articles Page

@app.route('/Articles')
def articles():
	return render_template('Articles.html', articles = Articles)

#single article

@app.route('/article/<string:id>/')
def article(id):
	return render_template('article.html', id=id)

# Register Form Class

class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# User Register

@app.route('/Register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
 
    return render_template('Register.html',form = form)

#log-in

@app.route('/Login', methods = ['GET','POST'])
def Login():
	if request.method == 'POST':
		#get form fields
		username = request.form['username']
		password_candidate = request.form['password']

		#create cursor
		
		cur = mysql.connection.cursor()

		#get user by username
		result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

		if result > 0:
			#get stored hash
			data = cur.fetchone()
			password = data['password']

			#compare password
			
			if sha256_crypt.verify(password_candidate, password):
				#passed
				session['logged_in'] = True
				session['username'] = username
				flash('You are in the zone', 'success')
				return redirect(url_for('Dashboard'))
			else:
				error = "invalid login"
				return render_template('login.html', error=error)
			#close session
			cur.close()
		else:
			error = "username not found"
			return render_template('login.html', error=error)
	return render_template('login.html')

#User-Authorization
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('Login'))
    return wrap



#Log-Out

@app.route('/Logout')
def Logout():
	session.clear()
	flash('You Are now Leaving the Zone', 'success')
	return redirect(url_for('Login'))
		
#Dashboard

@app.route('/Dashboard')
@is_logged_in
def Dashboard():

	return render_template('Dashboard.html')
if __name__ == '__main__':
	app.secret_key='secret123'
	app.run(debug=True) 