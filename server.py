from functools import wraps
import hashlib
import json
from os import environ as env
from urllib.parse import urlencode
from urllib.request import urlopen
import uuid

from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import (
    abort,
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from jose import jwt


load_dotenv()

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)


def get_token_auth_header():
    """Obtains the Access Token from the Authorization Header"""
    auth = request.headers.get("Authorization", None)
    if not auth:
        return None
    parts = auth.split()
    if parts[0].lower() != "bearer" or len(parts) != 2:
        return None
    return parts[1]


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        if not token:
            return (
                jsonify(
                    {
                        "code": "authorization_header_missing",
                        "description": "Authorization header is expected",
                    }
                ),
                401,
            )

        try:
            jsonurl = urlopen(
                f'https://{env.get("AUTH0_DOMAIN")}/.well-known/jwks.json'
            )
            jwks = json.loads(jsonurl.read())

            payload = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],
                audience=env.get("AUTH0_AUDIENCE"),
                issuer=f'https://{env.get("AUTH0_DOMAIN")}/',
            )
        except jwt.ExpiredSignatureError as jwt_expired_error:
            print(jwt_expired_error)
            return (
                jsonify({"code": "token_expired", "description": "token is expired"}),
                401,
            )
        except jwt.JWTClaimsError as jwt_claims_error:
            print(jwt_claims_error)
            return (
                jsonify(
                    {
                        "code": "invalid_claims",
                        "description": "incorrect claims, please check the audience and issuer",
                    }
                ),
                401,
            )
        except Exception as catch_all_exception:
            print(catch_all_exception)
            return (
                jsonify(
                    {
                        "code": "invalid_header",
                        "description": "Unable to parse authentication token.",
                    }
                ),
                401,
            )

        return f(*args, **kwargs)

    return decorated


@app.route("/")
def home():
    user = session.get("user")
    return render_template("home.html", user=user)


@app.route("/login")
def login():
    session["nonce"] = uuid.uuid4().hex
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True),
        nonce=session.get("nonce"),
        audience=env.get("AUTH0_AUDIENCE"),  # Important to get JWS over JWE
    )


@app.route("/callback")
def callback():
    token = oauth.auth0.authorize_access_token()
    userinfo = oauth.auth0.parse_id_token(token, nonce=session.get("nonce"))

    session["user"] = {
        "sub": userinfo["sub"],
        "name": userinfo.get("name"),
        "email": userinfo.get("email"),
    }
    session["access_token"] = token["access_token"]
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    user = session.get("user")
    if not user:
        return redirect(url_for("home"))
    return render_template("dashboard.html", user=user)


@app.route("/logout")
def logout():
    session.clear()
    params = {
        "returnTo": url_for("home", _external=True),
        "client_id": env.get("AUTH0_CLIENT_ID"),
    }
    return redirect(f"https://{env.get('AUTH0_DOMAIN')}/v2/logout?{urlencode(params)}")


@app.route("/api/hello")
@requires_auth
def api_hello():
    return jsonify({"message": "Hello, authenticated user!"})


if __name__ == "__main__":
    app.run(
        host="127.0.0.1", port=5000, debug=True, ssl_context=("cert.pem", "key.pem")
    )
