from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

#from flask_bcrypt import Bcrypt
#from flask_httpauth import HTTPBasicAuth #created by Miguel Grinberg
#from flask_recaptcha import ReCaptcha

# init app and config
app = Flask(__name__)
app.config['SECRET_KEY'] = '60339867c2c323b1f9afefbc297129c0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app) 

login_manager = LoginManager(app)
#bcrypt = Bcrypt(app)

## init Recaptcha
#app.config.update(dict(
#    RECAPTCHA_ENABLED = True,
#    RECAPTCHA_SITE_KEY = "public",
#    RECAPTCHA_SECRET_KEY = "private",
#))

#recaptcha = ReCaptcha()
#recaptcha.init_app(app)
#recaptcha = ReCaptcha(app=app)

# custom vars
# How long until Api keys expire after generatoin
KEY_DURATION_SECS = 24*60*60 # 24 * 60 * 60 = 24 hours

# How many rounds will bcrypt use for hashes
SALT_ROUNDS = 15

# required at bottom in order to prevent circular dependancy, after everything has been intialised
from flask_api import views
