from flask import Flask, session, redirect, render_template, request,url_for
from auth import setup_masterpasswd, verify_masterpasswd, is_first_run
from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length
from vault import get_all_entries, add_entry, delete_entry
from utils import generate_password




app = Flask(__name__)
app.config["SECRET_KEY"] = "akdjfadsjfifelkjne"
app.config['SESSION_PERMANENT'] = False



class Signup(FlaskForm):
    password = PasswordField(
        'Password', validators=[DataRequired(),Length(min=8, max=100, 
        message='password has to fall btw %(min)s and %(max)s') ,
        EqualTo('confirm', message='Passwords must match!.')]
    )
    confirm = PasswordField('Confirm', validators=[DataRequired()])
    create = SubmitField('Create')

class Login(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    unlock = SubmitField('Unlock')

    


@app.route('/', methods=['GET'])
def index():
    if not session.get("password"):
        return redirect(url_for('login'))

    else:
       return redirect(url_for('vault'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    signup = Signup()
    login = Login()
    state = is_first_run()
    if signup.validate_on_submit():
        passwd = signup.password.data 
        setup_masterpasswd(passwd=passwd)
        session['password'] = passwd
        return redirect(url_for('vault'))
    if login.validate_on_submit():
        passwd = login.password.data 
        if verify_masterpasswd(passwd=passwd):
            session["password"] = passwd
            return redirect(url_for('vault'))
        else:
            return render_template('login.html', login=login ,state=state,signup=signup, msg='Incorrect password!.')
    
    return render_template('login.html',state=state, login=login, signup=signup)

@app.route('/vault', methods=['GET'])
def vault():
    passwd = session.get("password")
    if not passwd:
        return redirect(url_for('login'))
    if not is_first_run() == False:
        session.clear()
        return redirect(url_for('login'))
    entries = get_all_entries(passwd=passwd)
    return render_template('vault.html', entries=entries)


@app.route('/add', methods=['POST'])
def add():
    passwd = session.get('password')
    if not passwd:
        return redirect(url_for('login'))

    service = request.form.get('service')
    username = request.form.get('username')
    password = request.form.get('password')

    add_entry(passwd=passwd, service=service, username=username, password=password)
    return redirect(url_for('vault'))



@app.route('/delete', methods=['POST'])
def delete():
    passwd = session.get("password")
    if not passwd:
        return redirect(url_for('login'))

    entry_id = request.form.get('entry_id')
    delete_entry(passwd=passwd, entry_id=entry_id)
    return redirect(url_for("vault"))


@app.route('/generate', methods=['GET'])
def generate():
    passwd = generate_password(12)
    return passwd


@app.route('/lock', methods=['POST'])
def lock():
    session.clear()
    return redirect(url_for('login'))










if __name__ == "__main__":
    app.run(debug=True)