from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import func, or_
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
import os
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from models import User, Project, Collaboration, Notification, Message, ProjectAttachment, Resource, Course, CourseReview, UserCourse
import json
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from flask_caching import Cache

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Configure caching
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()  # In case of database errors
    return render_template('500.html'), 500

@app.errorhandler(RateLimitExceeded)
def ratelimit_handler(e):
    return render_template('rate_limit_exceeded.html', error=str(e)), 429

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    user_count = User.query.count()
    project_count = Project.query.filter_by(status='Open').count()
    collaboration_count = Collaboration.query.filter_by(status='Completed').count()
    recent_projects = Project.query.order_by(Project.created_at.desc()).limit(5).all()
    return render_template('home.html', user_count=user_count, project_count=project_count, collaboration_count=collaboration_count, recent_projects=recent_projects)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    skills = StringField('Skills (comma-separated)', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, skills=form.skills.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Logged in successfully.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'error')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_projects = Project.query.filter_by(creator_id=current_user.id).all()
    collaborations = Collaboration.query.filter_by(collaborator_id=current_user.id).all()
    
    # Add recommended projects based on user skills
    user_skills = current_user.skills.split(',')
    recommended_projects = Project.query.filter(
        Project.creator_id != current_user.id,
        func.lower(Project.description).contains(func.lower(user_skills[0]))
    ).limit(5).all()

    return render_template('dashboard.html', user_projects=user_projects, collaborations=collaborations, recommended_projects=recommended_projects)

class CreateProjectForm(FlaskForm):
    title = StringField('Project Title', validators=[DataRequired(), Length(min=5, max=100)])
    description = TextAreaField('Project Description', validators=[DataRequired(), Length(min=20, max=1000)])
    skills_needed = StringField('Skills Needed (comma-separated)', validators=[DataRequired()])
    submit = SubmitField('Create Project')

@app.route('/create_project', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per hour")
def create_project():
    form = CreateProjectForm()
    if form.validate_on_submit():
        project = Project(
            title=form.title.data,
            description=form.description.data,
            creator=current_user,
            skills_needed=form.skills_needed.data
        )
        db.session.add(project)
        db.session.commit()
        flash('Project created successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_project.html', form=form)

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')  # Change 'query' to 'q'
    page = request.args.get('page', 1, type=int)
    users = User.query.filter(User.skills.like(f'%{query}%')).paginate(page=page, per_page=10)
    projects = Project.query.filter(Project.title.like(f'%{query}%') | Project.description.like(f'%{query}%')).paginate(page=page, per_page=10)
    return render_template('search.html', users=users, projects=projects, query=query)

@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('profile.html', user=user)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.bio = request.form['bio']
        current_user.location = request.form['location']
        current_user.portfolio_url = request.form['portfolio_url']
        current_user.skills = request.form['skills']
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile', username=current_user.username))
    return render_template('edit_profile.html')

@app.route('/project/<int:project_id>')
@login_required
def project_details(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template('project_details.html', project=project)

@app.route('/request_collaboration/<int:project_id>', methods=['POST'])
@login_required
def request_collaboration(project_id):
    project = Project.query.get_or_404(project_id)
    if project.creator_id == current_user.id:
        flash('You cannot collaborate on your own project.', 'error')
    else:
        role = request.form.get('role', 'Collaborator')
        collaboration = Collaboration(project_id=project_id, collaborator_id=current_user.id, role=role)
        db.session.add(collaboration)
        
        notification = Notification(
            user_id=project.creator_id,
            message=f"{current_user.username} has requested to collaborate on your project '{project.title}'."
        )
        db.session.add(notification)
        
        db.session.commit()
        flash('Collaboration request sent.', 'success')
    return redirect(url_for('project_details', project_id=project_id))

@app.route('/find_collaborators')
@login_required
def find_collaborators():
    user_skills = set(current_user.skills.split(','))
    potential_collaborators = User.query.filter(
        User.id != current_user.id
    ).all()

    # Calculate skill match percentage for each user
    collaborators = []
    for user in potential_collaborators:
        user_skills_set = set(user.skills.split(','))
        match_percentage = len(user_skills.intersection(user_skills_set)) / len(user_skills) * 100
        collaborators.append({
            'user': user,
            'match_percentage': round(match_percentage, 2)
        })

    # Sort collaborators by match percentage (highest first)
    collaborators.sort(key=lambda x: x['match_percentage'], reverse=True)

    return render_template('find_collaborators.html', collaborators=collaborators)

@app.route('/notifications')
@login_required
def notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifications)

@app.route('/rate_collaboration/<int:collaboration_id>', methods=['POST'])
@login_required
def rate_collaboration(collaboration_id):
    collaboration = Collaboration.query.get_or_404(collaboration_id)
    if collaboration.project.creator_id != current_user.id:
        flash('You can only rate collaborations on your own projects.', 'error')
    else:
        rating = int(request.form['rating'])
        collaboration.rating = rating
        db.session.commit()
        flash('Collaboration rated successfully.', 'success')
    return redirect(url_for('project_details', project_id=collaboration.project_id))

@app.route('/send_message/<int:recipient_id>', methods=['POST'])
@login_required
def send_message(recipient_id):
    recipient = User.query.get_or_404(recipient_id)
    content = request.form['content']
    message = Message(sender_id=current_user.id, recipient_id=recipient_id, content=content)
    db.session.add(message)
    db.session.commit()
    flash('Message sent successfully.', 'success')
    return redirect(url_for('view_messages', user_id=recipient_id))

@app.route('/messages/<int:user_id>')
@login_required
def view_messages(user_id):
    other_user = User.query.get_or_404(user_id)
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.created_at).all()
    return render_template('messages.html', messages=messages, other_user=other_user)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_attachment/<int:project_id>', methods=['POST'])
@login_required
def upload_attachment(project_id):
    project = Project.query.get_or_404(project_id)
    if project.creator_id != current_user.id:
        flash('You can only upload attachments to your own projects.', 'error')
        return redirect(url_for('project_details', project_id=project_id))

    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('project_details', project_id=project_id))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('project_details', project_id=project_id))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        attachment = ProjectAttachment(project_id=project_id, filename=filename, file_path=file_path)
        db.session.add(attachment)
        db.session.commit()

        flash('File uploaded successfully', 'success')
    else:
        flash('Invalid file type', 'error')

    return redirect(url_for('project_details', project_id=project_id))

@app.route('/courses')
@cache.cached(timeout=300)  # Cache for 5 minutes
def courses():
    search = request.args.get('search', '')
    selected_category = request.args.get('category', '')
    
    query = Course.query
    
    if search:
        query = query.filter(or_(Course.title.ilike(f'%{search}%'), 
                                 Course.description.ilike(f'%{search}%')))
    
    if selected_category:
        query = query.filter(Course.category == selected_category)

    courses = query.all()

    categories = db.session.query(Course.category).distinct().all()
    categories = [cat[0] for cat in categories if cat[0]]  # Remove None values

    context = {
        'courses': courses,
        'search_term': search,
        'selected_category': selected_category,
        'categories': categories,
    }
    return render_template('courses.html', **context)

def make_cache_key(*args, **kwargs):
    path = request.path
    args = str(hash(frozenset(request.args.items())))
    return (path + args).encode('utf-8')

@app.route('/course/<int:course_id>')
@cache.cached(timeout=300, key_prefix=make_cache_key)
def course_details(course_id):
    course = Course.query.get_or_404(course_id)
    user_course = None
    if current_user.is_authenticated:
        user_course = UserCourse.query.filter_by(user_id=current_user.id, course_id=course_id).first()
    return render_template('course_details.html', course=course, user_course=user_course)

@app.route('/course/<int:course_id>/enroll', methods=['POST'])
@login_required
def enroll_course(course_id):
    course = Course.query.get_or_404(course_id)
    if UserCourse.query.filter_by(user_id=current_user.id, course_id=course_id).first():
        flash('You are already enrolled in this course.', 'info')
    else:
        user_course = UserCourse(user_id=current_user.id, course_id=course_id)
        db.session.add(user_course)
        db.session.commit()
        flash('You have successfully enrolled in the course!', 'success')
    return redirect(url_for('course_details', course_id=course_id))

@app.route('/course/<int:course_id>/continue')
@login_required
def continue_course(course_id):
    user_course = UserCourse.query.filter_by(user_id=current_user.id, course_id=course_id).first_or_404()
    flash('Welcome back! Continue your learning journey.', 'info')
    return redirect(url_for('course_details', course_id=course_id))

@app.route('/course/<int:course_id>/update-progress', methods=['POST'])
@login_required
def update_course_progress(course_id):
    user_course = UserCourse.query.filter_by(user_id=current_user.id, course_id=course_id).first_or_404()
    progress = request.form.get('progress', type=float)
    if progress is not None:
        user_course.progress = progress
        if progress >= 100:
            user_course.completed = True
            user_course.completed_at = datetime.utcnow()
        db.session.commit()
        flash('Your progress has been updated.', 'success')
    return redirect(url_for('course_details', course_id=course_id))

@app.route('/certifications')
@login_required
def certifications():
    available_certifications = Certification.query.all()
    return render_template('certifications.html', available_certifications=available_certifications)

@app.route('/certification/<int:certification_id>')
@login_required
def certification_details(certification_id):
    certification = Certification.query.get_or_404(certification_id)
    user_cert = UserCertification.query.filter_by(user_id=current_user.id, certification_id=certification_id).first()
    return render_template('certification_details.html', certification=certification, user_cert=user_cert)

@app.route('/view_certificate/<int:certification_id>')
@login_required
def view_certificate(certification_id):
    user_cert = UserCertification.query.filter_by(user_id=current_user.id, certification_id=certification_id).first_or_404()
    # Here you would generate or retrieve the certificate file
    # For now, we'll just render a template with the certificate information
    return render_template('view_certificate.html', user_cert=user_cert)

class ResourceForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=5, max=100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=20, max=500)])
    resource_type = SelectField('Resource Type', choices=[('template', 'Template'), ('tool', 'Tool'), ('guide', 'Guide')], validators=[DataRequired()])
    file = FileField('File', validators=[DataRequired()])
    submit = SubmitField('Add Resource')

@app.route('/resources', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per hour")
def resources():
    form = ResourceForm()
    if form.validate_on_submit():
        file = form.file.data
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'resources', filename)
            file.save(file_path)

            new_resource = Resource(
                title=form.title.data,
                description=form.description.data,
                file_path=file_path,
                resource_type=form.resource_type.data,
                created_by=current_user.id
            )
            db.session.add(new_resource)
            db.session.commit()
            flash('Resource added successfully', 'success')
            return redirect(url_for('resources'))
        else:
            flash('Invalid file type', 'error')

    resources = Resource.query.all()
    return render_template('resources.html', form=form, resources=resources)

@app.route('/resources/<int:resource_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def resource_details(resource_id):
    resource = Resource.query.get_or_404(resource_id)

    if request.method == 'GET':
        return render_template('resource_details.html', resource=resource)

    elif request.method == 'PUT':
        if resource.created_by != current_user.id:
            flash('You can only edit your own resources', 'error')
            return redirect(url_for('resources'))

        resource.title = request.form['title']
        resource.description = request.form['description']
        resource.resource_type = request.form['resource_type']

        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'resources', filename)
                file.save(file_path)
                resource.file_path = file_path

        db.session.commit()
        flash('Resource updated successfully', 'success')
        return redirect(url_for('resource_details', resource_id=resource.id))

    elif request.method == 'DELETE':
        if resource.created_by != current_user.id:
            flash('You can only delete your own resources', 'error')
            return redirect(url_for('resources'))

        db.session.delete(resource)
        db.session.commit()
        flash('Resource deleted successfully', 'success')
        return redirect(url_for('resources'))

@app.route('/download_resource/<int:resource_id>')
@login_required
def download_resource(resource_id):
    resource = Resource.query.get_or_404(resource_id)
    return send_file(resource.file_path, as_attachment=True)

@app.route('/api/resource', methods=['GET'])
@limiter.limit("100 per day")
@login_required
def api_resource():
    # ... (your API logic here)

@cache.memoize(timeout=3600)  # Cache for 1 hour
def get_user_statistics(user_id):
    # Perform expensive calculation here
    user = User.query.get(user_id)
    projects_count = Project.query.filter_by(creator_id=user_id).count()
    collaborations_count = Collaboration.query.filter_by(collaborator_id=user_id).count()
    # ... more calculations ...
    return {
        'projects_count': projects_count,
        'collaborations_count': collaborations_count,
        # ... more stats ...
    }

@app.route('/user/<int:user_id>/statistics')
@login_required
def user_statistics(user_id):
    stats = get_user_statistics(user_id)
    return render_template('user_statistics.html', stats=stats)

def populate_ai_courses():
    ai_courses = [
        {
            "title": "AI-Powered Python Programming",
            "description": "Learn Python programming with the help of AI-powered coding assistants and personalized exercises.",
            "instructor": "AI Tutor",
            "duration": 40,
            "category": "Programming",
            "curriculum": "Module 1: Python Basics\nModule 2: Data Structures\nModule 3: Functions and OOP\nModule 4: AI-Assisted Coding Projects",
            "ai_powered": True,
            "ai_features": json.dumps({
                "code_completion": "AI-powered code suggestions and auto-completion",
                "personalized_exercises": "Dynamically generated coding challenges based on student progress",
                "error_analysis": "AI-driven error detection and explanation",
                "adaptive_learning": "Customized learning path based on student performance"
            })
        },
        {
            "title": "Machine Learning Fundamentals",
            "description": "Explore the basics of machine learning with interactive AI-driven simulations and real-time feedback.",
            "instructor": "AI Professor",
            "duration": 60,
            "category": "Data Science",
            "curriculum": "Module 1: Introduction to ML\nModule 2: Supervised Learning\nModule 3: Unsupervised Learning\nModule 4: Neural Networks and Deep Learning",
            "ai_powered": True,
            "ai_features": json.dumps({
                "interactive_simulations": "AI-powered ML model simulations",
                "real_time_feedback": "Instant AI-generated feedback on assignments",
                "adaptive_quizzes": "AI-curated quizzes based on student weaknesses",
                "project_assistant": "AI guidance for ML projects"
            })
        }
    ]

    for course_data in ai_courses:
        course = Course.query.filter_by(title=course_data['title']).first()
        if course is None:
            new_course = Course(**course_data)
            db.session.add(new_course)
    
    db.session.commit()

def make_cache_key(*args, **kwargs):
    path = request.path
    args = str(hash(frozenset(request.args.items())))
    return (path + args).encode('utf-8')

@app.route('/user/<username>')
@cache.cached(timeout=300, key_prefix=make_cache_key)
def user_profile(username):
    # Your view logic here
    pass

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    # Update profile logic here
    # ...
    cache.delete_memoized(get_user_statistics, current_user.id)
    flash('Profile updated successfully', 'success')
    return redirect(url_for('profile', username=current_user.username))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        populate_ai_courses()
    app.run(debug=True)