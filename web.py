import hashlib

from flask import Flask, make_response, redirect, request

app = Flask(__name__)


@app.route("/go")
def go():
    # CWE-601 open redirect, CodeQL py/url-redirection, Medium 6.1
    return redirect(request.args.get("next", "/"))


@app.route("/hello")
def hello():
    # CWE-79 reflected cross site scripting, py/reflective-xss, Medium 6.1
    resp = make_response("Hello " + request.args.get("name", ""))
    # CWE-614 cookie without the secure flag, py/insecure-cookie, Medium 5.0
    resp.set_cookie("session", "abc123", secure=False)
    return resp


@app.route("/login", methods=["POST"])
def login():
    # CWE-327 weak hash for a password, py/weak-sensitive-data-hashing, High 7.5
    return hashlib.md5(request.form["password"].encode()).hexdigest()


if __name__ == "__main__":
    # CWE-215 debug mode in production, py/flask-debug, High 7.5
    app.run(debug=True)
