import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    # return apology("TODO")
    stocks = db.execute(
        "select distinct symbol from purchases where symbol != 'NULL' and user_id = ?", session["user_id"])
    holding1 = 0
    stocklist = []
    for stock in stocks:
        symbol = stock["symbol"]
        stock_info = lookup(symbol)
        if stock_info:
            price = stock_info["price"]
            shares = db.execute(
                "select sum(shares) from purchases where user_id = ? and symbol = ?", session["user_id"], symbol)
            holding = shares[0]["sum(shares)"] * price
            holding1 += holding
            stocklist.append(
                {"symbol": symbol, "shares": shares[0]["sum(shares)"], "price": f"{price:.2f}", "holding": f"{holding:.2f}"})
    cash = db.execute("select cash from users where id = ?", session["user_id"])[0]["cash"]
    grand = holding1 + cash
    formated_cash = f"{cash:.2f}"
    formatted_grand = f"{grand:.2f}"

    return render_template("index.html", stocks=stocklist, cash_bal=formated_cash, total=formatted_grand)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # return apology("TODO")
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbols = request.form.get("symbol")
        result = lookup(request.form.get("symbol"))
        if not result:
            return apology("no results")
        price = float(result["price"])

        share = request.form.get("shares")
        if not share.isdigit() or int(share) <= 0:
            return apology("not valid number of shares")
        share = int(share)
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        user_cash = float(user_cash)
        if user_cash < price * share:
            return apology("Not enough money")
        timestamp = datetime.now()
        db.execute("insert into purchases (user_id, symbol, shares, price, timestamp) values(?, ?, ?, ?, ?)",
                   session["user_id"], symbols, share, price, timestamp)
        user_cash = user_cash - (price * share)
        db.execute("UPDATE users set cash = cash - ? where id = ?",
                   price * share, session["user_id"])
    return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # return apology("TODO")
    history = db.execute("select * from purchases where user_id = ?", session["user_id"])
    formated = []
    for row in history:
        formated.append({
            "symbol": row["symbol"],
            "shares": row["shares"],
            "price": f"{row['price']:.2f}",
            "timestamp": row["timestamp"]
        })
    return render_template("history.html", history_table=formated)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    session.clear()

    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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


    session.clear()

    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""


    if request.method == "GET":
        return render_template("quote.html")
    else:
        result = lookup(request.form.get("symbol"))
        if not result:
            return apology("TODO")
    return render_template("quoted.html", name=result["name"], price=f"{result['price']:.2f}", symbol=result["symbol"])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "GET":
        return render_template("register.html")
    else:
        name = request.form.get("username")
        if not name:
            return apology("TODO")
        try:
            name = str(name)
        except ValueError:
            return apology("Username taken")
        password = request.form.get("password")
        if not password:
            return apology("TODO")
        confirmation = request.form.get("confirmation")
        if not confirmation:
            return apology("TODO")
        if not password == confirmation:
            return apology("TODO")
        if db.execute("SELECT username from users where username = ?", name):
            return apology("Username already taken")
    secure_pas = generate_password_hash(password)
    db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", name, secure_pas)
    return redirect("/login")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # return apology("TODO")
    if request.method == "GET":
        stocks = db.execute(
            "SELECT symbol FROM purchases WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0",
            session["user_id"]
        )
        if not stocks:
            return apology("You don't own any stocks to sell.")
        return render_template("sell.html", stocks=stocks)
    else:
        stocks = db.execute(
            "select distinct symbol from purchases where symbol != 'NULL' and user_id = ?", session["user_id"])
        stocklist = []
        for stock in stocks:
            symbol = stock["symbol"]
            stocklist.append(symbol)

        share = int(request.form.get("shares"))
        symbol = request.form.get("symbol")

        user_shares = db.execute(
            "select sum(shares) as total_shares from purchases where user_id = ? and symbol = ?", session["user_id"], symbol)
        total_shares = user_shares[0]["total_shares"]
        if share <= 0 or share > total_shares:
            return apology("should be positive")
        if symbol not in stocklist:
            return apology("you do not have stocks")
        symbol_price = lookup(request.form.get("symbol"))
        benefit = symbol_price["price"] * share
        timestamp = datetime.now()
        negative_shares = -share
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", benefit, session["user_id"])
        db.execute("INSERT INTO purchases (user_id, symbol, shares, price, timestamp) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], symbol, negative_shares, symbol_price["price"], timestamp)

    return redirect("/")
