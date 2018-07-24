from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from decimal import Decimal
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        # check for username
        if not request.form.get("username"):
            return apology("Please enter username.")

        # check for password
        elif not request.form.get("password"):
            return apology("Please enter password.")

        # check for password confirmation
        elif not request.form.get("confirmation"):
            return apology("Please confirm password.")

        # check for matching passwords
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords do not match.")

        # insert new user into database
        result = db.execute("INSERT INTO users (username, hash) \
                             VALUES (:username, :hash)", \
                             username=request.form.get("username"), \
                             hash=generate_password_hash(request.form.get("password")))

        # if username exists
        if not result:
            return apology("Choose another username.")

        # successful registration redirect
        return render_template("login.html")

    # registration redirect
    else:
        return render_template("register.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

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
        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """Change user password"""

    if request.method =="POST":
        # check form filled
        if not request.form.get("oldpassword"):
            return apology("Enter old password")

        elif not request.form.get("newpassword"):
            return apology("Enter new password")

        elif not request.form.get("confirmation"):
            return apology("Confirm new password")

        # check for matching new password
        elif request.form.get("newpassword") != request.form.get("confirmation"):
            return apology("Passwords do not match")

        # query for current password hash
        oldhash = db.execute("SELECT hash FROM users WHERE id=:id", \
                              id=session["user_id"])

        # check current password validity
        if not check_password_hash(oldhash[0]["hash"], request.form.get("oldpassword")):
            return apology("Re-enter current password")

        # hash and update new password
        db.execute("UPDATE users SET hash=:hash WHERE id=:id", \
                    hash=generate_password_hash(request.form.get("newpassword")), \
                    id=session["user_id"])

        return redirect("/")

    else:
        return render_template("settings.html")



@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # populate user portfolio
    wallet = db.execute("SELECT shares, symbol FROM portfolio \
                         WHERE id=:id", id=session["user_id"])
    balance = 0

    # iterate through user-owned stocks
    for stock in wallet:
        symbol = stock["symbol"]
        shares = stock["shares"]
        stockinfo = lookup(symbol)
        total = int(shares) * float(stockinfo["price"])

        balance += total

        # update user portfolio
        db.execute("UPDATE portfolio SET price=:price, \
                    total=:total WHERE id=:user_id AND symbol=:symbol", \
                    price=usd(stockinfo["price"]), total=usd(total), \
                    user_id=session["user_id"], symbol=symbol)

    # load user cash balance from users database
    cash = db.execute("SELECT cash FROM users WHERE id=:user_id", \
                        user_id=session["user_id"])

    # update balance
    balance += cash[0]["cash"]

    # query database for user portfolio
    portfolio = db.execute("SELECT * FROM portfolio WHERE id=:user_id", \
                            user_id=session["user_id"])
    print(portfolio)
    return render_template("index.html", portfolio=portfolio, \
                            cash=usd(cash[0]["cash"]), \
                            total=usd(balance))




@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():

    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        try:
            shares = int(shares)
        except ValueError:
            return apology("Invalid quantity requested")
        else:

            if symbol == None:
                return apology("Unrecognized stock symbol")

            elif shares < 0:
                return apology("No refunds. Negative value entered")

            else:
                stock = lookup(symbol)
                if lookup(symbol) == None:
                    return apology("Stock symbol not found")

                # calculate total stock cost
                cost = shares * lookup(symbol)["price"]

                # check cash in user's wallet
                cash = db.execute("SELECT cash FROM users WHERE \
                                   id=:user_id;", user_id=session["user_id"])

                # calculate balance after purchase
                balance = cash[0]["cash"] - cost
                if balance < 0:
                    return apology("Insufficient funds.")

                else:
                    # update history of transactions
                    db.execute("INSERT INTO transactions (symbol, shares, price, id) \
                                VALUES(:symbol, :shares, :price, :user_id)", \
                                symbol=stock["symbol"], shares=shares, \
                                price=usd(stock["price"]), user_id=session["user_id"])

                    # update cash in users
                    db.execute("UPDATE users SET cash = cash - :purchase WHERE id=:user_id", \
                                user_id=session["user_id"], purchase=stock["price"] * shares)

                    # calculate number of shares owned
                    owned = db.execute("SELECT shares, total FROM portfolio WHERE id=:user_id \
                                               AND symbol=:symbol", user_id=session["user_id"], \
                                               symbol=stock["symbol"])

                    if owned:
                        # update shares in portfolio
                        total_shares = owned[0]["shares"] + shares
                        total_dec = Decimal(owned[0]["total"].strip('$'))
                        total_value = float(total_dec) + cost

                        db.execute("UPDATE portfolio SET shares=:shares, total=:total \
                                    WHERE id=:user_id AND symbol=:symbol", \
                                    shares=total_shares, total=total_value, \
                                    user_id=session["user_id"], symbol=stock["symbol"])

                    else:
                        # add portfolio record of stock
                        db.execute("INSERT INTO portfolio (name, shares, price, total, symbol, id) \
                                    VALUES(:name, :shares, :price, :total, :symbol, :user_id)", \
                                    name=stock["name"], shares=shares, price=usd(stock["price"]), \
                                    total=usd(shares * stock["price"]), symbol=stock["symbol"], \
                                    user_id=session["user_id"])


        # Redirect user to home page
        return redirect("/")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # query transactions from transaction database
    transactions = db.execute("SELECT * FROM transactions WHERE \
                               id=:user_id", user_id=session["user_id"])

    return render_template("history.html", transactions=transactions)



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
        symbol = lookup(request.form.get("symbol"))

        if symbol == None:
            return apology("Invalid symbol")

        price = usd(symbol["price"])
        return render_template("quoted.html", stock=symbol, price=price)

    else:
        return render_template("quote.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "GET":
        portfolio = db.execute("SELECT symbol FROM portfolio WHERE \
                                id=:user_id", user_id=session["user_id"])
        return render_template("sell.html", portfolio=portfolio)

    else:
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        if not symbol:
            return apology("Select symbol")

        # ensure positive integer input
        if not shares or shares < 1:
            return apology("Enter a positive number of shares to sell")

        # query user portfolio
        user_stocks = db.execute("SELECT symbol, shares FROM portfolio WHERE \
                                  id=:user_id AND symbol=:symbol", user_id=session["user_id"], \
                                  symbol=symbol)

        # subtract quantity of shares from currently owned
        available = int(user_stocks[0]["shares"])
        if available < shares:
            return apology("Insufficient shares")

        # update remaining shares
        available -= shares

        # lookup current value of share
        shareval = lookup(symbol)["price"]
        value = shareval * shares

        # query and update user balance
        userbal = db.execute("SELECT cash FROM users WHERE id=:user_id", \
                              user_id=session["user_id"])
        balance = userbal[0]["cash"]
        balance += value

        # update user portfolio databse
        db.execute("UPDATE portfolio SET shares=:shares, price=:price, \
                    total=:balance WHERE id=:user_id AND symbol=:symbol", \
                    shares=available, price=shareval, balance=balance, \
                    user_id=session["user_id"], symbol=symbol)

        # remove stock record if no shares remain
        if available == 0:
            db.execute("DELETE FROM portfolio WHERE shares=0")

        # insert record into transactions database
        db.execute("INSERT INTO transactions (symbol, shares, price, id) \
                    VALUES(:symbol, :shares, :price, :user_id)", \
                    symbol=symbol, shares=shares, price=value, \
                    user_id=session["user_id"])

        # update users database for cash (increase balance)
        db.execute("UPDATE users SET cash=:balance WHERE id=:user_id", \
                    user_id=session["user_id"], balance=balance)

    # Redirect user to home page
    return redirect("/")



def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)



# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
