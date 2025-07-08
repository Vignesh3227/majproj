from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:MumbaiIndians%405@localhost:5432/Jira'

db = SQLAlchemy(app)
ma = Migrate(app, db)


class TimestampMixin:
    created_at=db.Column(db.DateTime, default=datetime.now)


class User(TimestampMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(100), nullable=False)
    password=db.Column(db.String(200), nullable=False)
    profile=db.relationship('UserProfile',  backref='profile', uselist=False)


class UserProfile(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    name=db.Column(db.String(100))
    phone=db.Column(db.String(10))
    status=db.Column(db.Boolean, default=False)

class Role(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    roles=db.Column(db.String(20), unique=True)


class UserRoles(TimestampMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role_id=db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)

    role=db.relationship('Role', backref='user_roles')
    user=db.relationship('User', backref='roles')


class Project(TimestampMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(50), nullable=False, unique=True)
    description=db.Column(db.Text, nullable=False)
    status=db.Column(db.Boolean, default=False)
    deadline=db.Column(db.DateTime, nullable=False)
    created_by=db.Column(db.Integer,db.ForeignKey('user.id'))

    created=db.relationship('User',backref='created_projects')


class Team(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(50), nullable=False, unique=True)


class TeamProject(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    team_id=db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    project_id=db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

    team=db.relationship('Team', backref='projects')
    project=db.relationship('Project', backref='teams')


class TeamMembers(TimestampMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    team_id=db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)

    team=db.relationship('Team', backref='members')
    user=db.relationship('User', backref='teams')


class Ticket(TimestampMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    title=db.Column(db.Text, nullable=False)
    status=db.Column(db.Boolean, default=False)
    priority=db.Column(db.String(10), nullable=False)
    due_date=db.Column(db.DateTime, nullable=False)
    project_id=db.Column(db.Integer, db.ForeignKey('project.id'))
    assignee_id=db.Column(db.Integer, db.ForeignKey('user.id'))

    project=db.relationship('Project', backref='tickets')
    assignee=db.relationship('User', backref='assigned_tickets')


class TicketDiscussion(TimestampMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    ticket_id=db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message=db.Column(db.Text, nullable=False)

    ticket=db.relationship('Ticket', backref='discussions')
    user=db.relationship('User', backref='ticket_discussions')

class Tasks(TimestampMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    task=db.Column(db.Text, nullable=False)
    project_id=db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    team_id=db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    status=db.Column(db.Boolean, default=False)
    due_date=db.Column(db.DateTime, nullable=False)
    assigned_by=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    project=db.relationship('Project', backref='tasks')
    team=db.relationship('Team', backref='tasks')
    user=db.relationship('User', backref='assigned_tasks')

class Sprints(TimestampMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    sprint=db.Column(db.Text, nullable=False)
    project_id=db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    due=db.Column(db.DateTime, nullable=False)
    status=db.Column(db.Boolean, default=False)

    project=db.relationship('Project',  backref='sprints')

class Notifications(TimestampMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type=db.Column(db.Text, nullable=False)
    content=db.Column(db.Text, nullable=False)
    is_read=db.Column(db.Boolean, default=False)

    user=db.relationship('User', backref='notifications')

# @app.route("/")
# def home():
#     return render_template('login.html')


# @app.route('/profile')
# def base1():
#     return render_template('profile.html')

# @app.route('/base')
# def base():
#     return render_template('base.html')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    # app.run(debug=True)