from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:MumbaiIndians%405@localhost:5432/Jira'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret'

db = SQLAlchemy(app)
ma = Migrate(app, db)
api = Api(app)
jwt = JWTManager(app)

#--------------------------------------------------------------MIXIN--------------------------------------------------------------------------------------------------------------
class TimestampMixin:
    created_at=db.Column(db.DateTime, default=datetime.now)

#-------------------------------------------------------------SCHEMA---------------------------------------------------------------------------------------------------------------

class User(TimestampMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(100), nullable=False)
    password=db.Column(db.String(200), nullable=False)
    profile=db.relationship('UserProfile',  backref='user', uselist=False)


class UserProfile(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    name=db.Column(db.String(100))
    phone=db.Column(db.String(10))
    status=db.Column(db.Boolean, default=False)

class Role(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    roles=db.Column(db.Enum("manager","developer","admin",name='roles_enum'), nullable=False)


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



#---------------------------------------------------------------------------------API-----------------------------------------------------------------------------------------------
def get_user_role(user_id):
    user_roles = UserRoles.query.filter_by(user_id=user_id).all()
    return [ur.role.roles for ur in user_roles]

def role_required(allowed_roles):
    def wrapper(fn):
        
        def decorator(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user_roles = get_user_role(current_user_id)
            if not any(role in allowed_roles for role in user_roles):
                return {"message": "Unauthorized: Insufficient role"}, 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

class ApproveRole(Resource):
    @jwt_required
    @role_required(["admin"])
    def post(self):
        data=request.get_json()
        user_id=data.get('user_id')
        role_name=data.get('role') 
        role = Role.query.filter_by(roles=role_name).first()
        if not role:
            return {"message": "Invalid role"}, 400
        if UserRoles.query.filter_by(user_id=user_id, role_id=role.id).first():
            return {"message": "User already has this role"}, 400
        user_role = UserRoles(user_id=user_id, role_id=role.id)
        db.session.add(user_role)
        profile = UserProfile.query.filter_by(user_id=user_id).first()
        if profile:
            profile.status = True
        db.session.commit()
        return {"message": f"Role '{role_name}' assigned to user {user_id}"}, 200

class Register(Resource):
    def post(self):
        data=request.get_json()
        email=data.get('email')
        password=data.get('password')
        hash_password=generate_password_hash(password)
        if not email or not password:
            return {"message":"email and password required"}, 400
        if User.query.filter_by(email=email).first():
            return {"message": "user already exists"},400
        new_data=User(email=email, password=hash_password)
        db.session.add(new_data)
        db.session.commit()
        return {"message":"Registered Successfully!"}, 201

class Login(Resource):
    def post(self):
        data=request.get_json()
        email=data.get('email')
        password=data.get('password')
        user=User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            return {"message": "Invalid credentials"}, 401
        access_token = create_access_token(identity=user.id)
        return {"access_token": access_token}, 200

class GenerateTicket(Resource):
    
    def post(self):
        data = request.get_json()
        ticket = Ticket(
            title=data['title'],
            priority=data['priority'],
            due_date=datetime.strptime(data['due_date'], '%Y-%m-%d'),
            project_id=data['project_id'],
            assignee_id=data['assignee_id']
        )
        db.session.add(ticket)
        db.session.commit()
        return {"message": "Ticket created"}, 201

class ProjectCreate(Resource):
    @role_required(["admin","manager"])
    
    def post(self):
        current_user_id = get_jwt_identity()
        data = request.get_json()
        project = Project(
            name=data.get('name'),
            description=data.get('description'),
            deadline=datetime.strptime(data.get('deadline'), '%Y-%m-%d'),
            created_by=current_user_id
        )
        db.session.add(project)
        db.session.commit()
        return {"message": "Project created successfully"}, 201


class ProjectList(Resource):
    def get(self):
        projects = Project.query.all()
        result = [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "deadline": p.deadline.strftime('%Y-%m-%d'),
                "status": p.status
            }
            for p in projects
        ]
        return jsonify(result)

class TicketList(Resource):
    def get(self):
        tickets = Ticket.query.all()
        result = [
            {
                "id": t.id,
                "title": t.title,
                "priority": t.priority,
                "status": t.status,
                "due_date": t.due_date.strftime('%Y-%m-%d'),
                "project_id": t.project_id,
                "assignee_id": t.assignee_id
            }
            for t in tickets
        ]
        return jsonify(result)

class TicketDetail(Resource):
    def get(self, id):
        ticket = Ticket.query.get_or_404(id)
        return {
            "id": ticket.id,
            "title": ticket.title,
            "priority": ticket.priority,
            "status": ticket.status,
            "due_date": ticket.due_date.strftime('%Y-%m-%d'),
            "project_id": ticket.project_id,
            "assignee_id": ticket.assignee_id
        }
    
    def put(self, id):
        ticket = Ticket.query.get_or_404(id)
        data = request.get_json()
        ticket.title = data.get('title', ticket.title)
        ticket.priority = data.get('priority', ticket.priority)
        ticket.status = data.get('status', ticket.status)
        ticket.due_date = datetime.strptime(data.get('due_date', ticket.due_date.strftime('%Y-%m-%d')), '%Y-%m-%d')
        ticket.project_id = data.get('project_id', ticket.project_id)
        ticket.assignee_id = data.get('assignee_id', ticket.assignee_id)
        db.session.commit()
        return {"message": "Ticket updated successfully"}


    def delete(self, id):
        ticket = Ticket.query.get_or_404(id)
        db.session.delete(ticket)
        db.session.commit()
        return {"message": "Ticket deleted successfully"}

class ProjectDetail(Resource):

    def get(self, id):
        project = Project.query.get_or_404(id)
        return {
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "deadline": project.deadline.strftime('%Y-%m-%d'),
            "status": project.status
        }

    @role_required(["manager","admin"])
    def put(self, id):
        project = Project.query.get_or_404(id)
        data = request.get_json()
        project.name = data.get('name', project.name)
        project.description = data.get('description', project.description)
        project.deadline = datetime.strptime(data.get('deadline', project.deadline.strftime('%Y-%m-%d')), '%Y-%m-%d')
        project.status = data.get('status', project.status)
        db.session.commit()
        return {"message": "Project updated successfully"}


    @role_required(["manager","admin"])
    def delete(self, id):
        project = Project.query.get_or_404(id)
        db.session.delete(project)
        db.session.commit()
        return {"message": "Project deleted successfully"}

class DiscussionList(Resource):
    def get(self):
        discussions = TicketDiscussion.query.all()
        return [{
            "id": d.id,
            "ticket_id": d.ticket_id,
            "user_id": d.user_id,
            "message": d.message
        } for d in discussions], 200

class DiscussionCreate(Resource):

    def post(self):
        data = request.get_json()
        discussion = TicketDiscussion(
            ticket_id=data['ticket_id'],
            user_id=get_jwt_identity(),
            message=data['message']
        )
        db.session.add(discussion)
        db.session.commit()
        return {"message": "Comment added"}, 201

class DiscussionDetail(Resource):

    def get(self, id):
        d = TicketDiscussion.query.get_or_404(id)
        return {
            "id": d.id,
            "ticket_id": d.ticket_id,
            "user_id": d.user_id,
            "message": d.message
        }


    def put(self, id):
        d = TicketDiscussion.query.get_or_404(id)
        data = request.get_json()
        d.message = data.get('message', d.message)
        db.session.commit()
        return {"message": "Comment updated"}

    def delete(self, id):
        d = TicketDiscussion.query.get_or_404(id)
        db.session.delete(d)
        db.session.commit()
        return {"message": "Comment deleted"}

class TaskList(Resource):

    def get(self):
        tasks = Tasks.query.all()
        return [{
            "id": t.id,
            "task": t.task,
            "project_id": t.project_id,
            "team_id": t.team_id,
            "status": t.status,
            "due_date": t.due_date.strftime('%Y-%m-%d'),
            "assigned_by": t.assigned_by
        } for t in tasks], 200

class TaskCreate(Resource):
    
    @role_required(["admin", "manager"])
    def post(self):
        data = request.get_json()
        task = Tasks(
            task=data['task'],
            project_id=data['project_id'],
            team_id=data['team_id'],
            due_date=datetime.strptime(data['due_date'], '%Y-%m-%d'),
            assigned_by=get_jwt_identity()
        )
        db.session.add(task)
        db.session.commit()
        return {"message": "Task created successfully"}, 201

class TaskDetail(Resource):
    
    def get(self, id):
        task = Tasks.query.get_or_404(id)
        return {
            "id": task.id,
            "task": task.task,
            "project_id": task.project_id,
            "team_id": task.team_id,
            "status": task.status,
            "due_date": task.due_date.strftime('%Y-%m-%d'),
            "assigned_by": task.assigned_by
        }
    @role_required(["manager","admin"])
    
    def put(self, id):
        task = Tasks.query.get_or_404(id)
        data = request.get_json()
        task.task = data.get('task', task.task)
        task.status = data.get('status', task.status)
        task.project_id = data.get('project_id', task.project_id)
        task.team_id = data.get('team_id', task.team_id)
        task.due_date = datetime.strptime(data.get('due_date', task.due_date.strftime('%Y-%m-%d')), '%Y-%m-%d')
        db.session.commit()
        return {"message": "Task updated successfully"}

    @role_required(["manager","admin"])
    
    def delete(self, id):
        task = Tasks.query.get_or_404(id)
        db.session.delete(task)
        db.session.commit()
        return {"message": "Task deleted successfully"}

class SprintList(Resource):
    
    def get(self):
        sprints = Sprints.query.all()
        return [{
            "id": s.id,
            "sprint": s.sprint,
            "project_id": s.project_id,
            "due": s.due.strftime('%Y-%m-%d'),
            "status": s.status
        } for s in sprints], 200

class SprintCreate(Resource):
    @role_required(["admin", "manager"])
    
    def post(self):
        data = request.get_json()
        sprint = Sprints(
            sprint=data['sprint'],
            project_id=data['project_id'],
            due=datetime.strptime(data['due'], '%Y-%m-%d'),
            status=data.get('status', False)
        )
        db.session.add(sprint)
        db.session.commit()
        return {"message": "Sprint created"}, 201

class SprintDetail(Resource):
    
    def get(self, id):
        s = Sprints.query.get_or_404(id)
        return {
            "id": s.id,
            "sprint": s.sprint,
            "project_id": s.project_id,
            "due": s.due.strftime('%Y-%m-%d'),
            "status": s.status
        }

    
    @role_required(["manager","admin"])
    def put(self, id):
        s = Sprints.query.get_or_404(id)
        data = request.get_json()
        s.sprint = data.get('sprint', s.sprint)
        s.project_id = data.get('project_id', s.project_id)
        s.due = datetime.strptime(data.get('due', s.due.strftime('%Y-%m-%d')), '%Y-%m-%d')
        s.status = data.get('status', s.status)
        db.session.commit()
        return {"message": "Sprint updated"}

    
    @role_required(["manager","admin"])
    def delete(self, id):
        s = Sprints.query.get_or_404(id)
        db.session.delete(s)
        db.session.commit()
        return {"message": "Sprint deleted"}


#------------------------------------------------------------------------------API RESOURCES----------------------------------------------------------------------------------------------
api.add_resource(Register,"/register_data")
api.add_resource(Login,"/login_data")
api.add_resource(ProjectCreate, "/projects")
api.add_resource(ProjectList, "/projects/all")
api.add_resource(ProjectDetail, "/projects/<int:id>")
api.add_resource(GenerateTicket, "/tickets")
api.add_resource(TicketList, "/tickets/all")
api.add_resource(TicketDetail, "/tickets/<int:id>")
api.add_resource(TaskCreate, "/tasks")
api.add_resource(TaskList, "/tasks/all")
api.add_resource(TaskDetail, "/tasks/<int:id>")
api.add_resource(DiscussionCreate, "/discussions")
api.add_resource(DiscussionList, "/discussions/all")
api.add_resource(DiscussionDetail, "/discussions/<int:id>")
api.add_resource(SprintCreate, "/sprints")
api.add_resource(SprintList, "/sprints/all")
api.add_resource(SprintDetail, "/sprints/<int:id>") 
api.add_resource(ApproveRole, "/approve-role")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True,port=3000)

