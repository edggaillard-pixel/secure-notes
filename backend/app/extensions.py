"""Instances partagées des extensions Flask (initialisées dans create_app)."""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# get_remote_address lit request.remote_addr. Grâce à ProxyFix (cf. __init__),
# c'est l'IP réelle transmise par Nginx et non celle du conteneur proxy.
limiter = Limiter(key_func=get_remote_address)
# GROGNON
