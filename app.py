import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
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
    # get the user's cash total
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    # get table of symbols and sum of transactions
    stocks = db.execute(
        "SELECT stock, SUM(quantity) AS shares FROM transactions WHERE user_ID = ? GROUP BY stock HAVING (SUM(quantity)) > 0", session["user_id"])
    total_stock_price = 0
    prices = {}
    # gets the quote to get the price of stock
    # the total value of each stock is price of stock times quantity
    for stock in stocks:
        quote = lookup(stock["stock"])
        prices[quote["symbol"]] = quote["price"]
        total_stock_price += prices[quote["symbol"]] * stock["shares"]
    # total value of everything is stock price + user's total cash
    total_cash = total_stock_price + user_cash
    return render_template("index.html", stocks=stocks, user_cash=user_cash, total_cash=total_cash, prices=prices)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # get the stock symbol, price of stock, and number of shares the user wants to buy
        sym = request.form.get("symbol")
        price = lookup(sym)
        share = request.form.get("shares")
        # get user's total cash
        users_cash = db.execute("SELECT cash FROM users WHERE id = ? ", session["user_id"])[0]["cash"]
        # checks for valid symbol
        if not sym:
            return apology("please provide valid symbol!", 400)
        elif price is None:
            return apology("please provide valid symbol!", 400)
        # checks that shares is a positive integer
        try:
            share = int(share)
            if share < 1:
                return apology("shares must be a positive integer", 400)
        except:
            return apology("shares must be a positive integer", 400)

        # total price of shares = # of shares * price of share
        price_of_shares = int(share) * price["price"]
        # makes sure user has enough money to buy shares
        if users_cash < (price_of_shares):
            return apology("cash is not sufficient", 400)
        # edits the sql database to account for buying a stock
        else:
            db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", price_of_shares, session["user_id"])
            db.execute("INSERT INTO transactions (user_ID, stock, quantity, price, operation) VALUES (?, ?, ?, ?, ?)", 
                       session["user_id"], sym.upper(), share, price_of_shares, "Bought")
            flash("Bought!")
            return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    stocks = db.execute("SELECT * FROM transactions WHERE user_ID = ?", session["user_id"])
    return render_template("history.html", stocks=stocks)


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
    if request.method == "POST":

        # get the quote for inputted stock symbol
        # check if stock symbol is valid
        quote = lookup(request.form.get("symbol"))
        if quote == None:
            return apology("Your stock symbol is not valid! Please try again", 400)
        else:
            return render_template("quoted.html", name=quote["name"], symbol=quote["symbol"], price=quote["price"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # get the username, password, and confirmed password from the form
        username = request.form.get("username")
        password = request.form.get("password")
        confirmed_password = request.form.get("confirmation")
        username_list = db.execute("SELECT * FROM users WHERE username = ?", username)
        # check if username was submitted
        # check if username is original
        # check if password was submitted and password confirmation were submitted
        # check if password matches confirmed password  
        if not username:
            return apology("must provide username!", 400)
        elif len(username_list) != 0:
            return apology("this username already exists!", 400)
        elif not password or not confirmed_password:
            return apology("must provide password!", 400)
        elif password != confirmed_password:
            return apology("passwords do not match!", 400)
        # create hash password
        hash_password = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?) ", username, hash_password,)
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # gets symbol of stock user wants to sell and number of shares they nwat to sell
        sym = request.form.get("symbol")
        shares_sold = request.form.get("shares")
        # checks if shares inputted is a positive integer
        try:
            shares_sold = int(shares_sold)
            if shares_sold < 1:
                return apology("shares must be a positive integer", 400)
        except:
            return apology("shares must be a positive integer", 400)
        # checks if symbol is inputted
        if not sym:
            return apology("missing symbol")
        #makes sure number of shares being sold is not more than what you have
        stocks = db.execute("SELECT SUM(quantity) as quantity FROM transactions WHERE user_ID = ? AND stock = ?;", 
                            session["user_id"], sym)[0]
        if shares_sold > stocks["quantity"]:
            return apology("You don't have this number of shares")
        # get price of stock
        price = lookup(sym)["price"]
        # get value of stocks sold
        shares_value = float(price) * float(shares_sold)
        # edits the sql database to account for buying a stock
        db.execute("INSERT INTO transactions (user_ID, stock, quantity, price, operation) VALUES (?, ?, ?, ?, ?)", 
                   session["user_id"], sym.upper(), -float(shares_sold), shares_value, "Sold")
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", shares_value, session["user_id"])
        flash("Sold!")
        return redirect("/")
    else:
        stocks = db.execute("SELECT stock FROM transactions WHERE user_ID = ? GROUP BY stock", session["user_id"])
        return render_template("sell.html", stocks=stocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
