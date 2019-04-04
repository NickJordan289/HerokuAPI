from flask_api import app, db
from flask_api.models import users, apikeys

db.create_all() # makes sure all tables exist

if __name__ == '__main__':
    # use port=80 to remove port requirement in url
	app.run(host='0.0.0.0', port=5000, debug=False) # 5000 is default for flask
