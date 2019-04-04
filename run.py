import os
from flask_api import app, db
from flask_api.models import users, apikeys

db.create_all() # makes sure all tables exist

if __name__ == '__main__':
    # use port=80 to remove port requirement in url
	port = int(os.environ.get('PORT'))
	app.run(host='0.0.0.0', port=port, debug=False) # 5000 is default for flask
