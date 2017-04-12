import bcrypt
import flask
import flask_login
import flask_mail

from .authentication_forms import  NewUserForm, ChangeUserForm, LoginForm, AuthenticationForm
from .users_forms import  RegistrationForm
from .. import logic
from sampledb.logic.authentication import insert_user_and_authentication_method_to_db
from ..logic.security_tokens import  verify_token
from .. import mail, db, login_manager
from ..models import AuthenticationType, Authentication, UserType, User

from . import frontend


@login_manager.user_loader
def load_user(user_id):
    try:
        user_id = int(user_id)
    except ValueError:
        return None
    return User.query.get(user_id)


@frontend.route('/confirm', methods=['GET', 'POST'])
def confirm_registration():
    token = flask.request.args.get('token')
    email = verify_token(token, salt='invitation', secret_key=flask.current_app.config['SECRET_KEY'])
    if email is None:
        return flask.abort(404)
    registration_form = RegistrationForm()
    if registration_form.email.data is None or registration_form.email.data == "":
        registration_form.email.data = email
    if registration_form.validate_on_submit():
        name = str(registration_form.name.data)
        user = User(name, email, UserType.PERSON)
        # check, if user sent confirmation email and registered himself
        erg = User.query.filter_by(name=str(user.name).title(), email=str(user.email)).first()
        # no user with this name and contact email in db => add to db
        if erg is None:
            u = User(str(user.name).title(), user.email, user.type)
            insert_user_and_authentication_method_to_db(u, registration_form.password.data, email, AuthenticationType.EMAIL)
            flask.flash('registration successfully')
            return flask.redirect(flask.url_for('frontend.index'))
        else:
            flask.flash('user exists, please contact administrator')
            return flask.redirect(flask.url_for('frontend.index'))
    else:
        print(registration_form.name.data)
        return flask.render_template('registration.html', registration_form=registration_form)


@frontend.route('/add_user', methods=['GET', 'POST'])
def useradd():
    form = NewUserForm()
    print('xxxxxxxx')
    if form.validate_on_submit():
        print('validate')
        # check, if login already exists
        login = Authentication.query.filter(Authentication.login['login'].astext == form.login.data).first()
        print(login)
        if login is None:
            if (form.type.data == 'O'):
                type = UserType.OTHER
            else:
                type = UserType.PERSON
            user = User(str(form.name.data).title(), str(form.email.data), type)
            if form.authentication_method.data == 'E':
                authentication_method = AuthenticationType.EMAIL
            else:
                authentication_method = AuthenticationType.OTHER
            insert_user_and_authentication_method_to_db(user, form.password.data, form.login.data,
                                                        authentication_method)
        else:
            flask.flash('user exists, please contact administrator')
            return flask.redirect(flask.url_for('frontend.index'))
    return flask.render_template('user.html', form=form)





