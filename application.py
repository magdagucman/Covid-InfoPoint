from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///grocery.db")


@app.route("/")
def index():
    listOfdicts = db.execute("SELECT product, store, availability, timestamp FROM availability ORDER BY timestamp DESC LIMIT 20")
    products = []
    stores = []
    availability = []
    time = []

    for dictionary in listOfdicts:
        products.append(dictionary['product'])
        stores.append(dictionary['store'])
        availability.append(dictionary['availability'])
        time.append(dictionary['timestamp'])

    length = len(products)
    return render_template("index.html", products=products, stores=stores, availability=availability, time=time, length=length)

@app.route("/availability", methods=["GET", "POST"])
@login_required
def availability():
    if request.method == "GET":
        return render_template("availability.html")

    else:
        product = request.form.get("product")
        store = request.form.get("store")
        availability = request.form.get("availability")

        store_id_list = db.execute("SELECT id FROM shops WHERE name=:name", name=store)
        store_id_dict = store_id_list[0]
        store_id = store_id_dict['id']

        product_id_list = db.execute("SELECT id FROM products WHERE name=:name", name=product)
        product_id_dict = product_id_list[0]
        product_id = product_id_dict['id']

        db.execute("INSERT INTO availability (product_id, store_id, product, store, availability) VALUES (:product_id, :store_id, :product, :store, :availability)",
        product_id=product_id, store_id=store_id, product=product, store=store, availability=availability)
        return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/availability")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/flour")
def flour():
    listOfdicts = db.execute("SELECT DISTINCT store, availability, timestamp FROM availability WHERE product='Flour' ORDER BY timestamp DESC")
    stores = []
    availability = []
    time = []

    for dictionary in listOfdicts:
        if dictionary['store'] not in stores:
            stores.append(dictionary['store'])
            availability.append(dictionary['availability'])
            time.append(dictionary['timestamp'])

    length = len(stores)
    return render_template("flour.html", stores=stores, availability=availability, time=time, length=length)

@app.route("/pasta")
def pasta():
    listOfdicts = db.execute("SELECT DISTINCT store, availability, timestamp FROM availability WHERE product='Pasta' ORDER BY timestamp DESC")
    stores = []
    availability = []
    time = []

    for dictionary in listOfdicts:
        if dictionary['store'] not in stores:
            stores.append(dictionary['store'])
            availability.append(dictionary['availability'])
            time.append(dictionary['timestamp'])

    length = len(stores)
    return render_template("pasta.html", stores=stores, availability=availability, time=time, length=length)

@app.route("/canned_tomatoes")
def canned_tomatoes():
    listOfdicts = db.execute("SELECT DISTINCT store, availability, timestamp FROM availability WHERE product='Canned Tomatoes' ORDER BY timestamp DESC")
    stores = []
    availability = []
    time = []

    for dictionary in listOfdicts:
        if dictionary['store'] not in stores:
            stores.append(dictionary['store'])
            availability.append(dictionary['availability'])
            time.append(dictionary['timestamp'])

    length = len(stores)
    return render_template("canned_tomatoes.html", stores=stores, availability=availability, time=time, length=length)

@app.route("/lidl")
def lidl():
    listOfdicts = db.execute("SELECT DISTINCT product, availability, timestamp FROM availability WHERE store='Lidl' ORDER BY timestamp DESC")
    products = []
    availability = []
    time = []

    for dictionary in listOfdicts:
        if dictionary['product'] not in products:
            products.append(dictionary['product'])
            availability.append(dictionary['availability'])
            time.append(dictionary['timestamp'])

    length = len(products)
    return render_template("lidl.html", products=products, availability=availability, time=time, length=length)

@app.route("/aldi")
def aldi():
    listOfdicts = db.execute("SELECT DISTINCT product, availability, timestamp FROM availability WHERE store='Aldi' ORDER BY timestamp DESC")
    products = []
    availability = []
    time = []

    for dictionary in listOfdicts:
        if dictionary['product'] not in products:
            products.append(dictionary['product'])
            availability.append(dictionary['availability'])
            time.append(dictionary['timestamp'])

    length = len(products)
    return render_template("aldi.html", products=products, availability=availability, time=time, length=length)

@app.route("/sainsburys")
def sainsburys():
    listOfdicts = db.execute("SELECT DISTINCT product, availability, timestamp FROM availability WHERE store LIKE 'Sainsbury%' ORDER BY timestamp DESC")
    products = []
    availability = []
    time = []

    for dictionary in listOfdicts:
        if dictionary['product'] not in products:
            products.append(dictionary['product'])
            availability.append(dictionary['availability'])
            time.append(dictionary['timestamp'])

    length = len(products)
    return render_template("sainsburys.html", products=products, availability=availability, time=time, length=length)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        username = request.form.get("username")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)

        # Ensure username does not exist in the database
        if len(rows) == 1:
            return apology("username already exists", 403)

        # Ensure e-mail was submitted
        if not request.form.get("e-mail"):
            return apology("must provide e-mail", 403)

        email=request.form.get("e-mail")

        # Query database for e-mail
        rows = db.execute("SELECT * FROM users WHERE email = :email", email=email)

        # Ensure username does not exist in the database
        if len(rows) == 1:
            return apology("e-mail already used", 403)

        # Ensure submitted text is formated as e-mail
        atcounter = 0
        dotcounter = 0
        for char in email:
            if char == '@':
                atcounter += 1
            if char == '.':
                dotcounter += 1

        if atcounter != 1 or not dotcounter > 0:
            return apology("Wrong e-mail format", 403)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 403)

        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure password and confirmation match
        if not password == confirmation:
            return apology("password and confirmation must be exactly the same", 403)


        # Insert new user into database
        db.execute("INSERT INTO users (username, hash, email) VALUES (:username, :password, :email)", username=username, password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8), email=email)
        return redirect("/")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
