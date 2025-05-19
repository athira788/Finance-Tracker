from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    make_response,
    send_file,
    g,
    jsonify,
)
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    current_user,
    logout_user,
    UserMixin,
)

import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import re
import os
import csv
from flask_mail import Mail, Message
import zipfile
import io
from dateutil.relativedelta import relativedelta
import pandas as pd
from datetime import datetime, timedelta
import smtplib
from flask_bcrypt import Bcrypt
from flask_session import Session
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from email.mime.text import MIMEText
from apscheduler.schedulers.background import BackgroundScheduler
from flask_login import login_required


app = Flask(__name__)
app.config['TESTING'] = True
app.secret_key = "MAj6nSGKhwJNaBYutFTsyqE6T6_SyYJOEzjP9q9K5e8"
bcrypt = Bcrypt(app)
DATABASE = "financeTracker.sqlite"
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "drithika20898@gmail.com"
app.config["MAIL_PASSWORD"] = "xbhj cbkl axgl whhg"
app.config["MAIL_DEFAULT_SENDER"] = "drithika20898@gmail.com"
mail = Mail(app)
s = URLSafeTimedSerializer(os.environ.get("SECRET_KEY", "your_secret_key"))


def get_db():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

login_manager = LoginManager()
login_manager.init_app(app)


login_manager.login_view = "index"


class User(UserMixin):
    def __init__(self, user_id, email, is_admin):
        self.id = user_id
        self.email = email
        self.is_admin = is_admin


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE uId = ?", (user_id,)).fetchone()
    if user:
        return User(user["uId"], user["emailId"], user["is_admin"]) 
    return None


@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    db = get_db()
    
    current_month = datetime.now().strftime("%Y-%m")
    first_day_of_month = datetime.now().replace(day=1)

    user_counts_week = []
    user_counts_month = []
    last_six_months_labels = []

    for week in range(4):
        start_date = first_day_of_month + timedelta(weeks=week)
        end_date = start_date + timedelta(days=6)
        
        count = db.execute(
            "SELECT COUNT(*) as count FROM users WHERE creation_date >= ? AND creation_date < ?",
            (start_date, end_date)
        ).fetchone()["count"]
        
        user_counts_week.append(count)

    for month in range(6):
        month_start = (datetime.now() - relativedelta(months=month)).replace(day=1)
        month_end = (month_start + relativedelta(months=1))

        month_label = month_start.strftime("%B %Y")
        last_six_months_labels.append(month_label)
        
        count = db.execute(
            "SELECT COUNT(*) as count FROM users WHERE creation_date >= ? AND creation_date < ?",
            (month_start, month_end)
        ).fetchone()["count"]
        
        user_counts_month.append(count)

    return render_template("admin_dashboard.html", users_this_month=user_counts_week, users_per_month=user_counts_month, last_six_months=last_six_months_labels)

@login_required
@app.route("/admin_profile", methods=["GET", "POST"])
def admin_profile():
    if "user_id" not in session:
        return redirect(url_for("index"))

    user_email = session["user_id"]
    db = get_db()
    if request.method == "POST":

        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        middle_name = request.form.get("middle_name")

        if not first_name or not last_name :
            flash("Please fill out all required fields.", "danger")
        else:
            db.execute(
                "UPDATE users SET firstName = ?, lastName = ?, middleName = ? WHERE uId = ?",
                (first_name, last_name, middle_name, user_email),
            )
            db.commit()
            flash("Profile updated successfully!", "success")

    user = db.execute(
        "SELECT firstName, lastName, middleName, emailId FROM users WHERE uId = ?",
        (user_email,),
    ).fetchone()
    db.close()

    html = render_template("admin_profile.html", user=user)
    response = make_response(html)
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/manage_users")
@login_required
def manage_users():
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    return render_template("manage_users.html", users=users)

@app.route("/view_feedbacks")
@login_required
def view_feedbacks():
    db = get_db()
    feedbacks = db.execute("SELECT * FROM feedback").fetchall()
    return render_template("view_feedbacks.html", feedbacks=feedbacks)

@app.route("/delete_feedback/<int:id>", methods=['POST'])
@login_required
def delete_feedback(id):
    db=get_db()
    result = db.execute("DELETE FROM feedback WHERE id = ?", (id,))
    db.commit()
    if result.rowcount > 0:
        flash("Feedback deleted successfully!", "success")
    else:
        flash("Feedback not found!", "error")

    return redirect(url_for("view_feedbacks"))


@app.route("/manage_categories")
@login_required
def manage_categories():
    db = get_db()
    categories = db.execute("SELECT * FROM categories").fetchall()
    return render_template("manage_categories.html", categories=categories)


@app.route("/add_category", methods=["POST"])
@login_required
def add_category():
    category_name = request.form["category_name"]
    db = get_db()
    db.execute("INSERT INTO categories (name) VALUES (?)", (category_name,))
    db.commit()
    return redirect(url_for("manage_categories"))


@app.route("/delete_category/<int:category_id>", methods=["GET"])
@login_required
def delete_category(category_id):
    db = get_db()
    db.execute("DELETE FROM categories WHERE cid = ?", (category_id,))
    db.commit()
    return redirect(url_for("manage_categories"))


@app.route("/edit_user/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE uId = ?", (user_id,)).fetchone()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("manage_users"))

    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")

        db.execute(
            "UPDATE users SET firstName = ?, lastName = ?, emailId = ? WHERE uId = ?",
            (first_name, last_name, email, user_id),
        )
        db.commit()
        flash("User updated successfully!", "success")
        return redirect(url_for("manage_users"))

    return render_template("edit_user.html", user=user)


from flask import request, jsonify


@app.route("/edit_category/<int:category_id>", methods=["POST"])
@login_required
def edit_category(category_id):
    new_category_name = request.json.get("category_name", "")

    if not new_category_name:
        return jsonify({"success": False, "message": "Category name is required"})

    db = get_db()
    db.execute(
        "UPDATE categories SET name = ? WHERE cid = ?", (new_category_name, category_id)
    )
    db.commit()
    db.close()

    return jsonify({"success": True})


@app.before_request
def load_notifications_and_reminders():
    g.unread_notifications = 0
    g.notifications = []
    g.unread_reminders = 0
    g.reminders = []
    g.all_alerts = [] 

    if "user_id" in session:
        user_email = session["email"]
        db = get_db()

        cursor = db.execute(
            """
            SELECT message, created_at, id, 'notification' as type
            FROM notifications 
            WHERE emailId = ? AND read = 0
            ORDER BY created_at DESC
            LIMIT 5;
        """,
            (user_email,),
        )
        g.notifications = cursor.fetchall()
        g.unread_notifications = len(g.notifications)

        cursor = db.execute(
            """
            SELECT message, reminder_date as created_at, id, 'reminder' as type 
            FROM reminders 
            WHERE user_id = ? AND read = 0 
            ORDER BY reminder_date ASC;
        """,
            (user_email,),
        )
        g.reminders = cursor.fetchall()
        g.unread_reminders = len(g.reminders)

        g.all_alerts = g.notifications + g.reminders

        g.all_alerts.sort(key=lambda alert: alert["created_at"], reverse=True)


@app.context_processor
def inject_notifications_and_reminders():
    return dict(
        unread_notifications=g.unread_notifications,
        unread_reminders=g.unread_reminders,
        notifications=g.notifications,
        reminders=g.reminders,
        all_alerts=g.all_alerts, 
    )


@app.route("/mark_reminder_as_read/<int:reminder_id>", methods=["POST"])
def mark_reminder_as_read(reminder_id):
    db = get_db()
    db.execute("UPDATE reminders SET read = 1 WHERE id = ?", (reminder_id,))
    db.commit()
    return jsonify(success=True)


def send_reminder_email(user_email, reminder_message):
    msg = MIMEText(reminder_message)
    msg["Subject"] = "Monthly Expense Reminder"
    msg["From"] = "drithika20898@gmail.com"  
    msg["To"] = user_email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(
            "drithika20898@gmail.com", "xbhj cbkl axgl whhg"
        )  
        server.sendmail("drithika20@gmail.com", user_email, msg.as_string())


def create_reminders(email):
    try:
        with app.app_context():  
            db = get_db()
            cursor = db.execute(
                """
                SELECT uId, emailId FROM users;
            """
            )
            users = cursor.fetchall()

            for user in users:
                cursor = db.execute(
                    """
                    SELECT c.name, e.date AS last_entry_date 
                    FROM expenses e,categories c
                    WHERE userId = ?
                    and c.cid=e.cid;
                """,
                    (user["uId"],),
                )
                last_entries = cursor.fetchall()
                for entry in last_entries:
                    category = entry["name"]
                    last_entry_date = entry["last_entry_date"]

                    last_entry_date_dt = datetime.strptime(last_entry_date, "%Y-%m-%d")
                    if (datetime.now().date() - last_entry_date_dt.date()).days == 30:
                     
                        reminder_exists = db.execute(
                            """
                            SELECT COUNT(*) FROM reminders 
                            WHERE user_id = ? AND category = ? AND reminder_date = ?;
                        """,
                            (user["uId"], category, last_entry_date_dt.date()),
                        ).fetchone()[0]

                        if reminder_exists == 0:
                            message = f"Reminder: You had an expense in '{category}' on {last_entry_date}. Consider reviewing your budget."
                            db.execute(
                                """
                                INSERT INTO reminders (user_id, category, reminder_date, message, read) 
                                VALUES (?, ?, ?, ?, 0);
                            """,
                                (
                                    user["emailId"],
                                    category,
                                    last_entry_date_dt.date(),
                                    message,
                                ),
                            )
                            send_reminder_email(user["emailId"], message)

                db.commit()
    except Exception as e:
        db.rollback() 
        print("Error creating reminders:", e)


def send_budget_exceeded_email(user_email):
    msg = MIMEText("Your total expenses have exceeded your budget.")
    msg["Subject"] = "Budget Exceeded Alert"
    msg["From"] = "drithika20898@gmail.com"
    msg["To"] = user_email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login("drithika20898@gmail.com", "xbhj cbkl axgl whhg")
        server.sendmail("drithika20898@gmail.com", user_email, msg.as_string())


def add_notification(user_email, message):
    conn = get_db()
    conn.execute(
        "INSERT INTO notifications (emailId, message, created_at) VALUES (?, ?, ?)",
        (user_email, message, datetime.now()),
    )
    conn.commit()
    conn.close()


@app.route("/mark_as_read/<int:notification_id>", methods=["POST"])
def mark_as_read(notification_id):
    db = get_db()
    db.execute("UPDATE notifications SET read = 1 WHERE id = ?", (notification_id,))
    db.commit()
    return jsonify(success=True)


@app.route("/notifications")
def notifications():
    if "user_id" not in session:
        return redirect(url_for("index"))

    user_email = session["user_id"]
    conn = get_db()
    notifications = conn.execute(
        "SELECT * FROM notifications WHERE emailId = ?", (user_email,)
    ).fetchall()
    conn.close()

    return render_template("notifications.html", notifications=notifications)


@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response




@app.route("/", methods=["GET", "POST"])
def index():
    reset_message = request.args.get("reset_message", "")

    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin_dashboard"))
        else:
            return redirect(url_for("dashboard"))

    success_message = ""
    errors = {}
    form_data = request.form.to_dict()

    if request.method == "POST":
        if "login_email" in request.form:
            email = request.form["login_email"]
            password = request.form["login_password"]
            db = get_db()

            user = db.execute(
                "SELECT * FROM users WHERE emailId = ?", (email,)
            ).fetchone()
            db.close()

            if user and bcrypt.check_password_hash(user["password"], password):
                user_obj = User(
                    user["uId"], user["emailId"], user["is_admin"]
                ) 
                login_user(user_obj)  
                session["user_id"] = user["uId"]
                session["email"] = user["emailId"]
                create_reminders(session["email"])
                if user["is_admin"] == 1:
                    return redirect(
                        url_for("admin_dashboard")
                    ) 
                else:
                    return redirect(
                        url_for("dashboard")
                    )  
            else:
                errors["login"] = "Invalid credentials, please try again."

        elif "signup_email" in request.form:
            first_name = request.form["first_name"]
            last_name = request.form["last_name"]
            middle_name = request.form["middle_name"]
            email = request.form["signup_email"]
            password = request.form["signup_password"]
            confirm_password = request.form["confirm_password"]
            monthly_budget = request.form["monthly_budget"]
            security_answer_1 = request.form["security_answer_1"]
            security_answer_2 = request.form["security_answer_2"]
            password_pattern = re.compile(r"^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$")

            if password != confirm_password:
                errors["confirm_password"] = "Passwords do not match, please try again."
            if not password_pattern.match(password):
                errors["signup_password"] = (
                    "Password must be at least 8 characters long, "
                    "include at least one uppercase letter, one number, "
                    "and one special character."
                )
            if not first_name:
                errors["first_name"] = "First name is required."
            if not last_name:
                errors["last_name"] = "Last name is required."
            if not email:
                errors["signup_email"] = "Email is required."
            if not password:
                errors["signup_password"] = "Password is required."
            if not confirm_password:
                errors["confirm_password"] = "Confirm password is required."
            if not monthly_budget:
                errors["monthly_budget"] = "Monthly budget is required."
            if not security_answer_1:
                errors["security_answer_1"] = (
                    "Answer to security question 1 is required."
                )
            if not security_answer_2:
                errors["security_answer_2"] = (
                    "Answer to security question 2 is required."
                )

            if not errors:
                hashed_password = bcrypt.generate_password_hash(password)
                creation_date = datetime.now().strftime("%Y-%m-%d")

                db = get_db()
                existing_user = db.execute(
                    "SELECT * FROM users WHERE emailId = ?", (email,)
                ).fetchone()
                if existing_user:
                    errors["signup_email"] = "Email already exists, please log in."
                else:
                    db.execute(
                        "INSERT INTO users (firstName, lastName, middleName, emailId, password, overallBudget, securityAnswerOne, securityAnswerTwo, creation_date,is_admin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,?)",
                        (
                            first_name,
                            last_name,
                            middle_name,
                            email,
                            hashed_password,
                            monthly_budget,
                            security_answer_1,
                            security_answer_2,
                            creation_date,
                            0,
                        ),
                    )
                    db.commit()
                    form_data.clear()
                    flash("Signup successful! Please log in.", "success")
                db.close()

        if errors:
            form_data["signup_password"] = ""
            form_data["confirm_password"] = ""
            return render_template(
                "index.html",
                errors=errors,
                form_data=form_data,
                success_message=success_message,
                reset_message=reset_message,
            )
    return render_template(
        "index.html",
        success_message=success_message,
        form_data=form_data,
        reset_message=reset_message,
    )


@app.route("/resetPassword", methods=["GET", "POST"])
def reset_password():
    error_messages = []

    if request.method == "POST":
        email = request.form.get("email", "")
        security_answer_1 = request.form.get("security_answer_1", "")
        security_answer_2 = request.form.get("security_answer_2", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE emailId = ?", (email,)).fetchone()
        if (
            user
            and user["securityAnswerOne"] == security_answer_1
            and user["securityAnswerTwo"] == security_answer_2
        ):
            
            token = s.dumps(email, salt="email-confirm")
            reset_url = url_for("reset_with_token", token=token, _external=True)

            
            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"To reset your password, visit the following link: {reset_url}"
            mail.send(msg)

            flash("A password reset link has been sent to your email.", "success")
            return redirect(url_for("index"))

        else:
            error_messages.append(
                "Email not found or something is wrong. Please check and try again."
            )

    return render_template("reset_password.html", error_messages=error_messages)


@app.route("/reset_with_token/<token>", methods=["GET", "POST"])
def reset_with_token(token):
    email = ""
    new_password = ""
    confirm_new_password = ""
    error_messages = []

    try:
        email = s.loads(
            token, salt="email-confirm", max_age=3600
        )  
    except SignatureExpired:
        error_messages.append("The reset link has expired.")
        return render_template("reset_password.html", error_messages=error_messages)
    except BadSignature:
        error_messages.append("The reset link is invalid.")
        return render_template("reset_password.html", error_messages=error_messages)

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_new_password = request.form.get("confirm_password", "")
        password_pattern = re.compile(r"^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE emailId = ?", (email,)).fetchone()

        if new_password == confirm_new_password:
            if not password_pattern.match(new_password):
                error_messages.append(
                    "Password must be at least 8 characters long, "
                    "include at least one uppercase letter, one number, "
                    "and one special character."
                )
            else:
                hashed_password = bcrypt.generate_password_hash(new_password).decode(
                    "utf-8"
                )
                db.execute(
                    "UPDATE users SET password = ? WHERE emailId = ?",
                    (hashed_password, email),
                )
                db.commit()
                flash("Password reset successful, please log in.", "success")
                return redirect(url_for("index"))
        else:
            error_messages.append("Passwords do not match.")

    return render_template(
        "reset_with_token.html", error_messages=error_messages, email=email, token=token
    )

def send_feedback_email(user_email):
    msg = MIMEText("Your feedback has been received. We will connect with your shortly. Thank you so much.")
    msg["Subject"] = "Received Your Valuable Feedback"
    msg["From"] = "drithika20898@gmail.com"  
    msg["To"] = user_email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(
            "drithika20898@gmail.com", "xbhj cbkl axgl whhg"
        )  
        server.sendmail("drithika20@gmail.com", user_email, msg.as_string())


@login_required
@app.route('/send_feedback', methods=['POST'])
def submit_feedback():
    feedback_data = request.json
    name = feedback_data.get('name')
    email = feedback_data.get('email')
    phone = feedback_data.get('phone')
    subject = feedback_data.get('subject')
    message = feedback_data.get('message')
    userid = session["user_id"]

    conn = sqlite3.connect('financeTracker.sqlite')
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO feedback (name, email, phone, subject, message,userid)
            VALUES (?, ?, ?, ?, ?,?)
        """, (name, email, phone, subject, message,userid))
        conn.commit()
        send_feedback_email(email)
        return jsonify(success=True)
    except Exception as e:
        conn.rollback()
        return jsonify(success=False, error=str(e))
    finally:
        conn.close()

@app.route("/get_expense_report", methods=["POST"])
@login_required
def get_expense_report():
    if "user_id" not in session:
        return redirect(url_for("index"))
    db=get_db()
    user_id = session["user_id"]
    selected_month = request.form.get("month")
    year = request.form.get("year")
    if( int(selected_month)<10):
        myear = (year)+"-0"+(selected_month)
    else:
        myear = (year)+"-"+(selected_month)

    monthly_category_expenses = db.execute(
        """
        SELECT c.name, SUM(e.amount) AS total
        FROM expenses e
        JOIN categories c ON e.cid = c.cid
        WHERE e.userId = ? AND strftime('%Y-%m', e.date) = ?
        GROUP BY c.name
        """,
        (user_id, myear),
    ).fetchall()

    overall_budget = db.execute(
        """
        SELECT overallBudget
        FROM users
        WHERE uId = ?
        """,
        (user_id,)
    ).fetchone()['overallBudget']

    report_data = {
        "expenses": {entry["name"]: entry["total"] for entry in monthly_category_expenses},
        "overall_budget": overall_budget,
    }

    return jsonify(report_data)



@login_required
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("index"))

    user_id = session["user_id"]
    db = get_db()

    user = db.execute(
        "SELECT firstName, overallBudget FROM users WHERE uId = ?", (user_id,)
    ).fetchone()

    if user:
        first_name = user["firstName"]
        total_budget = user["overallBudget"]
    else:
        first_name = "User"
        total_budget = 0

    current_month = datetime.now().month
    current_year = datetime.now().year

    total_expenses = db.execute(
        """
        SELECT SUM(amount) AS total 
        FROM expenses 
        WHERE userId = ? AND 
        strftime('%m', date) = ? AND 
        strftime('%Y', date) = ?
        """, (user_id, f"{current_month:02d}", str(current_year))
    ).fetchone()["total"] or 0

    balance = total_budget - total_expenses

    monthly_expenses = db.execute(
    """
    SELECT strftime('%Y-%m', date) AS month, SUM(amount) AS total
    FROM expenses
    WHERE userId = ? 
    AND date >= date('now', '-6 months')
    GROUP BY month
    ORDER BY month DESC
    """,
    (user_id,),
).fetchall()


    category_expenses = db.execute(
    """
    SELECT c.name, SUM(e.amount) AS total
    FROM expenses e
    JOIN categories c ON e.cid = c.cid
    WHERE e.userId = ? AND strftime('%Y-%m', e.date) = strftime('%Y-%m', 'now')
    GROUP BY c.name
    ORDER BY total DESC
    """,
    (user_id,),).fetchall()

    monthly_category_expenses = db.execute(
    """
    SELECT strftime('%Y-%m', e.date) AS month, c.name, SUM(e.amount) AS total
    FROM expenses e
    JOIN categories c ON e.cid = c.cid
    WHERE e.userId = ? 
    AND e.date >= date('now', '-6 months')
    GROUP BY month, c.name
    ORDER BY month DESC, c.name
    """,
    (user_id,),).fetchall()
    
    current_month = datetime.now().strftime('%Y-%m')
    current_year = datetime.now().year
    
    monthly_total_expenses = db.execute(
    """
    SELECT SUM(e.amount) AS total_expenses
    FROM expenses e
    WHERE e.userId = ? AND strftime('%Y-%m', e.date) = ?
    """,
    (user_id, current_month)).fetchone()['total_expenses'] or 0

    user_budget = db.execute(
    """
    SELECT overallBudget
    FROM users
    WHERE uId = ?
    """,
    (user_id,)).fetchone()['overallBudget']

    monthly_labels = [entry["month"] for entry in monthly_expenses]
    monthly_values = [entry["total"] for entry in monthly_expenses]

    category_labels = [entry["name"] for entry in category_expenses]
    category_values = [entry["total"] for entry in category_expenses]

    category_monthly_data = {}
    for entry in monthly_category_expenses:
        month = entry["month"]
        name = entry["name"]
        total = entry["total"]

        if month not in category_monthly_data:
            category_monthly_data[month] = {}
        category_monthly_data[month][name] = total

    category_monthly_labels = list(category_monthly_data.keys())
    category_monthly_values = {name: [] for name in category_labels}

    for month in category_monthly_labels:
        for name in category_labels:
            category_monthly_values[name].append(
                category_monthly_data[month].get(name, 0)
            )

    chart_data = {
    "expenses": monthly_total_expenses,
    "remaining_budget": user_budget 
    }

    return render_template(
        "dashboard.html",
        first_name=first_name,
        total_budget=total_budget,
        total_expenses=total_expenses,
        balance=balance,
        monthly_labels=monthly_labels,
        monthly_values=monthly_values,
        category_labels=category_labels,
        category_values=category_values,
        category_monthly_labels=category_monthly_labels,
        category_monthly_values=category_monthly_values,
        chart_data = chart_data,
        current_year = current_year,
    )




@login_required
@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect(url_for("index"))

    user_email = session["user_id"]
    db = get_db()
    if request.method == "POST":
        if "delete_account" in request.form:
            db.execute("DELETE FROM users WHERE uId = ?", (user_email,))
            db.commit()
            db.close()
            session.pop("user_id", None)
            flash("Account deleted successfully!", "success")
            return redirect(url_for("index"))

        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        middle_name = request.form.get("middle_name")
        monthly_budget = request.form.get("monthly_budget")

        if not first_name or not last_name or not monthly_budget:
            flash("Please fill out all required fields.", "danger")
        else:
            db.execute(
                "UPDATE users SET firstName = ?, lastName = ?, middleName = ?, overallBudget = ? WHERE uId = ?",
                (first_name, last_name, middle_name, monthly_budget, user_email),
            )
            db.commit()
            flash("Profile updated successfully!", "success")

    user = db.execute(
        "SELECT firstName, lastName, middleName, overallBudget, emailId FROM users WHERE uId = ?",
        (user_email,),
    ).fetchone()
    db.close()

    html = render_template("profile.html", user=user)
    response = make_response(html)
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@login_required
@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "user_id" not in session:
        return redirect(url_for("index"))

    user_email = session["user_id"]
    db = get_db()

    db.execute("DELETE FROM users WHERE emailId = ?", (user_email,))
    db.commit()
    db.close()

    session.pop("user_id", None)
    flash("Account deleted successfully!", "deletesuccess")

    response = make_response(redirect(url_for("index")))
    return response

@login_required
@app.route("/add_expense", methods=["GET", "POST"])
def add_expense():
    if "user_id" not in session:
        return redirect(url_for("index"))

    conn = get_db()
    user_email = session["user_id"]
    recurring_expenses = conn.execute(
        "SELECT * FROM expenses WHERE is_recurring = ? AND userId =?", (1, user_email)
    ).fetchall()

    if request.method == "POST":
        expense_name = request.form["expense_name"]
        amount = float(request.form["amount"])
        date = request.form["date"]
        category = request.form["category"]
        notes = request.form["notes"]
        is_recurring = 1 if "is_recurring" in request.form else 0
        files = request.files.getlist("documents")

        cur = conn.cursor()
        cur.execute(
            "INSERT INTO expenses (name, amount, date, cid, notes, is_recurring, userId) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (expense_name, amount, date, category, notes, is_recurring, user_email),
        )
        expense_id = cur.lastrowid
        conn.commit()

        total_expenses = conn.execute(
            "SELECT SUM(amount) as total FROM expenses WHERE userId = ?", (user_email,)
        ).fetchone()["total"]
        budget = conn.execute(
            "SELECT overallBudget FROM users WHERE uId = ?", (user_email,)
        ).fetchone()
        overall_budget = float(budget["overallBudget"])

        if total_expenses > overall_budget:
            send_budget_exceeded_email(session["email"])
            add_notification(session["email"], f"Budget exceeded by ${total_expenses-overall_budget}")
        for file in files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                cur.execute(
                    "UPDATE expenses SET file_name = ? WHERE eid = ?",
                    (filename, expense_id),
                )
                conn.commit()

        conn.close()
        flash("Expense added successfully!", "success")
        return redirect(url_for("add_expense"))

    categories = conn.execute("SELECT cid, name FROM categories").fetchall()
    conn.close()

    return render_template(
        "add_expense.html", categories=categories, recurring_expenses=recurring_expenses
    )


@login_required
@app.route("/view_expense", methods=["GET"])
def view_expense():
    if "user_id" not in session:
        return redirect(url_for("index"))
    user_email = session["user_id"]
    search_query = request.args.get("search", "")
    selected_category = request.args.get("category", "")

    conn = get_db()
    users = conn.execute(
        "SELECT uId FROM users WHERE emailId = ?", (user_email,)
    ).fetchone()

    query = "SELECT * FROM expenses WHERE userId = ?"

    params = [user_email]

    if search_query:
        query += " AND name LIKE ?"
        params.append(f"%{search_query}%")

    if selected_category:
        query += " AND cid = ?"
        params.append(selected_category)

    expenses = conn.execute(query, params).fetchall()

    categories = conn.execute("SELECT * FROM categories")
    category_map = {category["cid"]: category["name"] for category in categories}
    conn.close()

    return render_template(
        "view_expense.html", expenses=expenses, category_map=category_map
    )


@login_required
@app.route("/download_expenses", methods=["POST"])
def download_expenses():
    if "user_id" not in session:
        return redirect(url_for("index"))

    selected_expenses = request.form.getlist("expense_ids")

    if not selected_expenses:
        flash("Please select at least one expense to download.", "danger")
        return redirect(url_for("view_expense"))

    db = get_db()

    expenses = db.execute(
        "SELECT * FROM expenses WHERE eid IN ({})".format(
            ",".join("?" * len(selected_expenses))
        ),
        tuple(selected_expenses),
    ).fetchall()
    expense_data = [
        {
            "Expense Name": expense["name"],
            "Amount": expense["amount"],
            "Date": expense["date"],
            "Category": expense["cid"],
            "Notes": expense["notes"],
        }
        for expense in expenses
    ]
    df = pd.DataFrame(expense_data)
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zip_file:
        excel_buffer = io.BytesIO()
        with pd.ExcelWriter(excel_buffer, engine="xlsxwriter") as writer:
            df.to_excel(writer, index=False, sheet_name="Expenses")
        zip_file.writestr("expenses_details.xlsx", excel_buffer.getvalue())
        for expense in expenses:
            if expense["file_name"]:
                documents = expense["file_name"].split(",")
                for doc in documents:
                    file_path = os.path.join(app.config["UPLOAD_FOLDER"], doc)
                    if os.path.exists(file_path):
                        custom_filename = f"{expense['name']}_{doc}"
                        zip_file.write(file_path, arcname=custom_filename)

    zip_buffer.seek(0)
    return send_file(
        zip_buffer,
        as_attachment=True,
        mimetype="application/zip",
        download_name="expenses.zip",
    )


@login_required
@app.route("/edit_expense/<int:expense_id>", methods=["GET", "POST"])
def edit_expense(expense_id):
    if "user_id" not in session:
        return redirect(url_for("index"))

    db = get_db()
    expense = db.execute(
        "SELECT * FROM expenses WHERE eid = ?", (expense_id,)
    ).fetchone()
    if not expense:
        flash("Expense not found.", "danger")
        return redirect(url_for("view_expense"))

    if request.method == "POST":
        cur = db.cursor()
        delete_document = request.form.get("delete_document")
        if delete_document:
            existing_docs = (
                expense["file_name"].split(",") if expense["file_name"] else []
            )
            if delete_document in existing_docs:
                existing_docs.remove(delete_document)
                file_path = os.path.join(app.config["UPLOAD_FOLDER"], delete_document)
                if os.path.exists(file_path):
                    os.remove(file_path)
                new_docs = ",".join(existing_docs)
                cur.execute(
                    "UPDATE expenses SET file_name = ? WHERE eid = ?",
                    (new_docs, expense_id),
                )
                db.commit()
        amount = request.form.get("amount")
        date = request.form.get("date")
        category = request.form.get("category")
        notes = request.form.get("notes")
        name = request.form.get("expense_name")
        amount = amount if amount else expense["amount"]
        date = date if date else expense["date"]
        category = category if category else expense["cid"]
        notes = notes if notes else expense["notes"]
        name = name if name else expense["name"]

        cur.execute(
            "UPDATE expenses SET amount = ?, date = ?, cid = ?, notes = ?, name = ? WHERE eid = ?",
            (amount, date, category, notes, name, expense_id),
        )
        db.commit()

        files = request.files.getlist("documents")
        new_files = []
        for file in files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(file_path)
                new_files.append(filename)

        if new_files:
            existing_docs = (
                expense["file_name"].split(",") if expense["file_name"] else []
            )
            all_docs = existing_docs + new_files
            new_docs = ",".join(all_docs)
            cur.execute(
                "UPDATE expenses SET file_name = ? WHERE eid = ?",
                (new_docs, expense_id),
            )
            db.commit()

        db.close()
        flash("Expense updated successfully!", "success")
        return redirect(url_for("edit_expense", expense_id=expense_id))

    categories = db.execute("SELECT cid, name FROM categories").fetchall()
    documents = expense["file_name"].split(",") if expense["file_name"] else []
    db.close()

    html = render_template(
        "edit_expense.html", expense=expense, categories=categories, documents=documents
    )
    response = make_response(html)
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@login_required
@app.route("/delete_expense/<int:expense_id>", methods=["POST"])
def delete_expense(expense_id):
    conn = get_db()
    conn.execute("DELETE FROM expenses WHERE eid = ?", (expense_id,))
    conn.commit()
    conn.close()
    flash("Expense deleted successfully!", "success")
    return redirect(url_for("view_expense"))


@login_required
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.clear()
    flash("You have been logged out.", "success")
    response = make_response(redirect(url_for("index")))
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


if __name__ == "__main__":
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)
