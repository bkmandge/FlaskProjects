from flask import Flask, request, render_template, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from middleware import auth, guest


app = Flask(__name__)
# session will use flask login module so need scret key for that session
app.secret_key = "49494asdkfghbmk"

# configuration for db connection
app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = "root"
app.config['MYSQL_PASSWORD'] = "root@2023"
app.config['MYSQL_DB'] = "flask_db"

# create instance of mysql(mysql) and pass your applications instance (app)
mysql = MySQL(app)

# initialise login manager
login_manage = LoginManager()

# initialises flask app's login module
login_manage.init_app(app)

# initialise bcrypt with flask application's instance
bcrypt = Bcrypt(app)

# to load user:- now to let login manager know from where to load users
@login_manage.user_loader
def load_user(user_id):
    return User.get(user_id)              


class User(UserMixin):
    def __init__(self, user_id, name, email):
        self.id = user_id
        self.name = name
        self.email = email
    
    @staticmethod
    def get(user_id):
        cursor = mysql.connection.cursor()
        # enter sql query here
        cursor.execute('SELECT name,email from users where id = %s',(user_id))
        result = cursor.fetchone()
        cursor.close()
        
        if result:
            return User(user_id, result[0], result[1])
        

@app.route("/")
def index():
    return "Home page"


@app.route("/login", methods = ["GET", "POST"])
def login():
    if request.method == "POST":
        # handle login -> when user submits form
        email = request.form["email"]
        password = request.form["password"]

        cursor = mysql.connection.cursor()
        cursor.execute('SELECT id, name, email, password from users where email = %s', (email,))
        user_data = cursor.fetchone()
        cursor.close()
        
        # check_password_hash = matches with previously entered password
        if user_data and bcrypt.check_password_hash(user_data[3], password):
            user = User(user_data[0], user_data[1], user_data[2])
            login_user(user)
            return redirect(url_for('dashboard'))        

    return render_template("login.html")  # includes html files content


@app.route("/register", methods = ["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        
        # to incrypt password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # store user details in db
        cursor = mysql.connection.cursor()
        
        cursor.execute('INSERT INTO users(name, email, password) values(%s, %s, %s)', (name, email, hashed_password))
        
        mysql.connection.commit()
        
        cursor.close()
        
        # now redirect user to login page 
        return redirect(url_for('login'))
        
    return render_template("register.html")


@app.route("/dashboard")
# middleware:- to prevent access / route protection
@login_required
# @guest:- custom middleware
def dashboard():
    return render_template("dashboard.html")

@app.route("/logout")
@login_required  # route protection
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug = True)   
    