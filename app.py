import os
from re import template

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']
    # Add a new table belongs to current user
    db.execute("CREATE TABLE IF NOT EXISTS ? (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE, symbol_of_stocks TEXT NOT NULL, amount REAL NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)", username)

    # Show the shares user current have
    stocks = db.execute("SELECT symbol_of_stocks FROM ?", username)
    stock_inf_list = []
    total_shares = 0
    for stock in stocks:
        # Collect all info(which is a dict for each share) into list "stock_inf_list"
        stock_inf = lookup(stock['symbol_of_stocks'])
        stock_inf["shares"] = db.execute("SELECT amount FROM ? WHERE symbol_of_stocks = ?", username, stock['symbol_of_stocks'])[0]['amount']
        stock_inf["cur_total"] = format(stock_inf["shares"]*stock_inf["price"],".2f")
        stock_inf_list.append(stock_inf)
        # Caculate the total share value
        total_shares = total_shares + float(stock_inf["cur_total"])
        # format all the money number
        stock_inf["price"] = usd(float(stock_inf["price"]))
        stock_inf["cur_total"] = usd(float(stock_inf["cur_total"]))

    cash = db.execute("SELECT cash FROM users WHERE username = ?", username)[0]['cash']
    total = cash + total_shares
    # formated all the numbers
    cash = usd(float(format(cash, ".2f")))
    total_shares = usd(total_shares)
    total = usd(total)
    return render_template("index.html",cash=cash, stock_inf_list=stock_inf_list, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Please check your input", 400)
        if not request.form.get("shares"):
            return apology("Please check your input", 400)

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        try:
            shares = int(shares)
        except:
            return apology("Shares must be a positive integer", 400)

        shares = int(shares)

        # Check the users input
        if not lookup(symbol):
            return apology("Such stock doesn't exit", 400)
        if (shares < 0):
            return apology("Shares must be a positive integer", 400)

        # Processing purchase
        # fomalize the input of symbol
        symbol = lookup(symbol)["symbol"]
        cur_price = lookup(symbol)["price"]
        user_id = session["user_id"]
        left_money = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        # If the user don't have enough money
        if left_money < cur_price * shares:
            return apology("Not enough money in your account", 400)

        # Create a new table for the transection if not exists(This code run only ones)
        db.execute("CREATE TABLE IF NOT EXISTS transaction_log (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE, username TEXT NOT NULL, symbol_of_stocks TEXT NOT NULL, amount REAL NOT NULL, trans_price REAL NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")

        # Edit in table for the MAIN log
        username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']
        current_price = lookup(symbol)["price"]
        db.execute("INSERT INTO transaction_log (username, symbol_of_stocks, amount, trans_price) VALUES (?, ?, ?, ?)", username, symbol, shares, current_price)

        # Edit in table for the current user
        if db.execute("SELECT * FROM ? WHERE symbol_of_stocks = ? ", username, symbol):
            # If bougt before, add into the current log
            share_have = db.execute("SELECT * FROM ? WHERE symbol_of_stocks = ? ", username, symbol)[0]["amount"]
            new_share = shares + share_have
            db.execute("UPDATE ? SET amount = ? WHERE symbol_of_stocks = ?", username, new_share, symbol)
        else:
            db.execute("INSERT INTO ? (symbol_of_stocks, amount) VALUES (?, ?)", username, symbol, shares)

        # deduct the money from database
        left_money = left_money - cur_price * shares
        db.execute("UPDATE users SET cash = ? WHERE id = ? ", left_money, user_id)

        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']

    trans_inf_list = db.execute("SELECT * FROM transaction_log WHERE username = ?", username)
    return render_template("history.html", trans_inf_list=trans_inf_list)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # if information is submited
    if request.method == "POST":
        symbol_u = request.form.get("symbol")
        stock_inf = lookup(symbol_u)

        return render_template("quoted.html", stock_inf=stock_inf)

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        # Password Check:
        # Input a username:
        if not request.form.get("username"):
            return apology("must provide username", 400)
        # Check if the name is already existed
        username = request.form.get("username") # username is a string
        if db.execute("SELECT * FROM users WHERE username=?", username):
            return apology("The user name has been taken", 400)
        # Check if there is a password
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        # Check if there is a repeated password
        elif not request.form.get("confirmation"):
            return apology("must type in password for twice", 400)
        # Check if both password inputs are the same
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("passwords typed in are not the same", 400)

        # Password Record:
        password = request.form.get("password")
        hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        # Register in the database
        db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", username, hash )
        return redirect("/")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']
    symbols = db.execute("SELECT symbol_of_stocks FROM ?", username)

    if request.method == "POST":
        # Get input from user
        symbol = request.form.get("symbol")
        sell_shares = float(request.form.get("shares"))

        # conditions
        cur_shares = db.execute("SELECT amount FROM ? WHERE symbol_of_stocks = ?", username, symbol)[0]['amount']
        if sell_shares > cur_shares:
            return apology("You don't have that much shares to sell!", 400)
        # Add money
        cur_price = float(lookup(symbol)["price"])
        gain = cur_price * sell_shares
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        cash = cash + gain
        db.execute("UPDATE users SET cash = ? WHERE id = ? ", cash, user_id)


        # remove the shares
        shares = cur_shares - sell_shares
        db.execute("UPDATE ? SET amount = ? WHERE symbol_of_stocks = ?", username, shares, symbol)

        # Record in log
        db.execute("INSERT INTO transaction_log (username, symbol_of_stocks, amount, trans_price) VALUES (?, ?, ?, ?)", username, symbol, -sell_shares, cur_price)

        return redirect("/")

    return render_template("sell.html", symbols=symbols)

@app.route("/buymore", methods=["GET", "POST"])
@login_required
def buymore():
    symbol = request.form.get("buyingshare")
    shares = 10

    # Processing purchase
    cur_price = lookup(symbol)["price"]
    user_id = session["user_id"]
    left_money = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    # If the user don't have enough money
    if left_money < cur_price * shares:
        return apology("Not enough money in your account", 400)

    # Edit in table for the MAIN log
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']
    current_price = lookup(symbol)["price"]
    db.execute("INSERT INTO transaction_log (username, symbol_of_stocks, amount, trans_price) VALUES (?, ?, ?, ?)", username, symbol, shares, current_price)

    # Edit in table for the current user
    if db.execute("SELECT * FROM ? WHERE symbol_of_stocks = ? ", username, symbol):
        # If bougt before, add into the current log
        share_have = db.execute("SELECT * FROM ? WHERE symbol_of_stocks = ? ", username, symbol)[0]["amount"]
        new_share = shares + share_have
        db.execute("UPDATE ? SET amount = ? WHERE symbol_of_stocks = ?", username, new_share, symbol)
    else:
        db.execute("INSERT INTO ? (symbol_of_stocks, amount) VALUES (?, ?)", username, symbol, shares)

    # deduct the money from database
    left_money = left_money - cur_price * shares
    db.execute("UPDATE users SET cash = ? WHERE id = ? ", left_money, user_id)

    return redirect("/")