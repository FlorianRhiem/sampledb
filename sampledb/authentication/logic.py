import bcrypt
import flask
import flask_mail
import flask_login
from flask_login import login_user

from .. import mail, db, login_manager
from .ldap import validate_user, get_user_info
from .models import  Authentication, AuthenticationType, User, UserType
from ..security_tokens import generate_token


def validate_user_db(login, password):
    authentication_methods = Authentication.query.filter(Authentication.login['login'].astext == login).all()
    for authentication_method in authentication_methods:
        if authentication_method.confirmed:
            if bcrypt.checkpw(password.encode('utf-8'), authentication_method.login['bcrypt_hash'].encode('utf-8')):
                user = authentication_method.user
                login_user(user)
                return True
    return False

def insert_user_and_authentication_method_to_db(user, password, login, user_type):
    db.session.add(user)
    db.session.commit()
    pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    login_data = {
        'login': login,
        'bcrypt_hash': pw_hash
    }
    add_authentication_to_db(login_data, user_type, True, user.id)

def send_confirm_email(email,id,salt):
    if id == None:
        token = generate_token(email, salt=salt,
                             secret_key=flask.current_app.config['SECRET_KEY'])
        confirm_url = flask.url_for(".confirm_registration", salt=salt, token=token, _external=True)
    else:
        token = generate_token([email, id], salt=salt,
                               secret_key=flask.current_app.config['SECRET_KEY'])
        confirm_url = flask.url_for(".confirm_email", salt=salt, token=token, _external=True)
    subject = "Please confirm your email"
    html    = flask.render_template('activate.html', confirm_url=confirm_url)
    mail.send(flask_mail.Message(
        subject,
        sender=flask.current_app.config['MAIL_SENDER'],
        recipients=[email],
        html=html
    ))


def add_authentication_to_db(log, user_type, confirmed, user_id):
    auth = Authentication(log, user_type, confirmed, user_id)
    db.session.add(auth)
    db.session.commit()


def login(login,password):
    # filter email + password or username + password or username (ldap)
    authentication_methods = Authentication.query.filter(
        db.or_(
            db.and_(Authentication.login['login'].astext == login,
                    Authentication.type == AuthenticationType.EMAIL),
            db.and_(Authentication.login['login'].astext == login,
                    Authentication.type == AuthenticationType.LDAP),
            db.and_(Authentication.login['login'].astext == login,
                    Authentication.type == AuthenticationType.OTHER)
        )
    ).all()

    for authentication_method in authentication_methods:
        # authentificaton method in db is ldap
        if authentication_method.type == AuthenticationType.LDAP:
            result = validate_user(login, password)
        else:
            result = validate_user_db(login, password)
        if result:
            user = authentication_method.user
            flask_login.login_user(user)
            return True

    # no authentificaton method in db
    if not authentication_methods and '@' not in login:
        # try to authenticate against ldap, if login is no email
        if not validate_user(login, password):
            return False

        new_user = get_user_info(login)
        assert new_user.type == UserType.PERSON
        user = User.query.filter_by(email=str(new_user.email), type=UserType.PERSON).first()
        if user is None:
            user = new_user
            db.session.add(user)
            db.session.commit()
        add_authentication_to_db({'login': login}, user_type=AuthenticationType.LDAP, confirmed=True, user_id=user.id)
        flask_login.login_user(user)
        return True
    return False


def add_login(userid, login, password, authentication_method):
    logins = Authentication.query.filter(Authentication.login['login'].astext == login,
                                        Authentication.user_id == userid).first()
    if logins is not None:
        # authentication-method already exists
        return False
    pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    log = {
        'login': login,
        'bcrypt_hash': pw_hash
    }

    if authentication_method == AuthenticationType.EMAIL:
        # check if login looks like an email
        if '@' not in login:
            return False
        else:
            # send confirm link
            send_confirm_email(login, userid, 'add_login')
            confirmed = False
    elif authentication_method == AuthenticationType.OTHER:
        confirmed = True
    else:
        if not validate_user(login, password):
            return False
        confirmed = True
    add_authentication_to_db(log, authentication_method, confirmed, userid)
    return True
