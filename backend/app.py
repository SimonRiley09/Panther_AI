from flask import Flask, flash, redirect, render_template, request, session, url_for
from authlib.integrations.flask_client import OAuth
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helper import login_required
from openai import OpenAI

# Configure application
app = Flask(__name__)
# Secret Key will be determined
app.secret_key = ''
oauth = OAuth(app)
client = OpenAI()

# Configure Google OAuth
# Need Secret key first
# ! Do Not Touch !
google = oauth.register(
    name='google',
    client_id='YOUR_GOOGLE_CLIENT_ID',
    client_secret='YOUR_GOOGLE_CLIENT_SECRET',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
)

# Fine Tuning job
# TO-DO
def fine_tuning():

    # TO-DO: copy code from 'https://platform.openai.com/docs/api-reference/fine-tuning?lang=python' training_file = training_data.jsonl model =4o mini


    # returns dic
    response = client.fine_tuning.jobs.list()

    # TO-DO: for loop in response["data"]; if status = succeed; return id
    # Example response 'https://platform.openai.com/docs/api-reference/fine-tuning/list?lang=python'

    # Delete pass and return model id
    pass

# returned model id will be passed here
def send_message(model_id, question):
    stream = client.chat.completions.create(
    model= model_id,
    messages=[{"role": "user", "content": question}],
    stream=True,
    )
    for chunk in stream:
        if chunk.choices[0].delta.content is not None:
            print(chunk.choices[0].delta.content, end="")


# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

def train_module():
    pass

# DO NOT TOUCH
@app.route('/')
def Index():
    user = session.get('user')
    if user:
        return redirect(url_for('Chat'))
    return '<a href="/login">Sign in with Google</a>'

# DO NOT TOUCH
@app.route('/login')
def login():
    return google.authorize_redirect(url_for('auth_callback', _external=True))

# DO NOT TOUCH
@app.route('/auth/callback')
def auth_callback():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    session['user'] = user_info
    return redirect(url_for('Index'))

@login_required
@app.route('/chat')
def Chat():
    if request.method == "POST":
        question = request.form.get("question")
        id = fine_tuning()
        send_message(model_id=id, question=question)

    # TO-DO FRONTEND: chat.html
    return render_template('chat.html')