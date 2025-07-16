import os
import csv
from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Ensure upload folder exists
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

ALLOWED_EXTENSIONS = {'csv', 'txt', 'pdf', 'jpg', 'jpeg', 'png'}

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    organization = db.Column(db.String(120))

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class QuestionnaireResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    section = db.Column(db.String(100))
    question = db.Column(db.String(300))
    answer = db.Column(db.String(200))
    comment = db.Column(db.Text)
    evidence_path = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_questionnaire():
    sections = {}
    with open('devweb.csv', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        current_dimension = None
        current_question_obj = None
        for row in reader:
            dimension = row['Dimensions'].strip()
            question = row['Questions'].strip()
            description = row['Description'].strip()
            option = row['Options'].strip()
            # New dimension starts
            if dimension:
                current_dimension = dimension
                if current_dimension not in sections:
                    sections[current_dimension] = []
            # New question starts
            if question:
                # Save previous question to section (if exists)
                if current_question_obj:
                    sections[current_dimension].append(current_question_obj)
                current_question_obj = {
                    'question': question,
                    'description': description,
                    'options': []
                }
            # Add option to current question
            if current_question_obj is not None and option:
                current_question_obj['options'].append(option)
        # Add last question
        if current_question_obj:
            sections[current_dimension].append(current_question_obj)
    return sections

QUESTIONNAIRE = load_questionnaire()
SECTION_IDS = list(QUESTIONNAIRE.keys())

def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                flash('Access denied!')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        organization = request.form.get('organization')
        # Server-side validation
        if not username or not email or not password or not role:
            flash('Please fill in all fields.')
            return redirect(url_for('register'))
        if role == 'client' and not organization:
            flash('Organization name required for client.')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        import re
        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
            flash('Invalid email format.')
            return redirect(url_for('register'))
        if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'\d', password):
            flash('Password must be at least 8 characters and include uppercase, lowercase, and number.')
            return redirect(url_for('register'))
        hash_pwd = generate_password_hash(password)
        user = User(username=username, email=email, password=hash_pwd, role=role, organization=organization)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid credentials.')
            return redirect(url_for('login'))
        session['user_id'] = user.id
        session['role'] = user.role
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required()
def dashboard():
    role = session['role']
    user_id = session['user_id']
    if role == 'client':
        products = Product.query.filter_by(owner_id=user_id).all()
        return render_template('dashboard_client.html', products=products)
    elif role == 'lead':
        resps = QuestionnaireResponse.query.all()
        return render_template('dashboard_lead.html', responses=resps)
    elif role == 'superuser':
        products = Product.query.all()
        clients = User.query.filter_by(role='client').all()
        return render_template('dashboard_superuser.html', products=products, clients=clients)
    return redirect(url_for('index'))

@app.route('/superuser/add_product_for_client', methods=['GET', 'POST'])
@login_required('superuser')
def add_product_for_client():
    if request.method == 'POST':
        name = request.form['name']
        client_id = request.form['client_id']
        if not name or not client_id:
            flash('Product name and client selection required.')
            return redirect(url_for('add_product_for_client'))
        
        client = User.query.get_or_404(client_id)
        if client.role != 'client':
            flash('Selected user is not a client.')
            return redirect(url_for('add_product_for_client'))
            
        product = Product(name=name, owner_id=client_id)
        db.session.add(product)
        db.session.commit()
        flash(f'Product "{name}" added for client {client.username}.')
        return redirect(url_for('dashboard'))
    
    clients = User.query.filter_by(role='client').all()
    return render_template('add_product_for_client.html', clients=clients)

@app.route('/superuser/client/<int:client_id>/products')
@login_required('superuser')
def view_client_products(client_id):
    client = User.query.get_or_404(client_id)
    if client.role != 'client':
        flash('Selected user is not a client.')
        return redirect(url_for('dashboard'))
    
    products = Product.query.filter_by(owner_id=client_id).all()
    return render_template('superuser_client_products.html', client=client, products=products)

@app.route('/superuser/product/<int:product_id>/statistics')
@login_required('superuser')
def view_product_statistics(product_id):
    product = Product.query.get_or_404(product_id)
    client = User.query.get_or_404(product.owner_id)
    resps = QuestionnaireResponse.query.filter_by(product_id=product_id).all()
    return render_template('superuser_product_statistics.html', product=product, client=client, responses=resps)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required('client')
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        if not name:
            flash('Product name required.')
            return redirect(url_for('add_product'))
        product = Product(name=name, owner_id=session['user_id'])
        db.session.add(product)
        db.session.commit()
        flash('Product added. Now fill the questionnaire.')
        return redirect(url_for('fill_questionnaire_section', product_id=product.id, section_idx=0))
    return render_template('add_product.html')

@app.route('/fill_questionnaire/<int:product_id>/section/<int:section_idx>', methods=['GET', 'POST'])
@login_required('client')
def fill_questionnaire_section(product_id, section_idx):
    product = Product.query.get_or_404(product_id)
    sections = SECTION_IDS
    if section_idx >= len(sections):
        flash("All sections complete!")
        return redirect(url_for('dashboard'))
    section_name = sections[section_idx]
    questions = QUESTIONNAIRE[section_name]
    if request.method == 'POST':
        for i, q in enumerate(questions):
            answer = request.form.get(f'answer_{i}')
            comment = request.form.get(f'comment_{i}')
            file = request.files.get(f'evidence_{i}')
            evidence_path = ""
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{product_id}_{section_idx}_{i}_{file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                evidence_path = filepath
            resp = QuestionnaireResponse(
                user_id=session['user_id'],
                product_id=product_id,
                section=section_name,
                question=q['question'],
                answer=answer,
                comment=comment,
                evidence_path=evidence_path
            )
            db.session.add(resp)
        db.session.commit()
        if section_idx + 1 < len(sections):
            return redirect(url_for('fill_questionnaire_section', product_id=product_id, section_idx=section_idx+1))
        else:
            flash("All sections completed. Thank you!")
            return redirect(url_for('dashboard'))
    completed_sections = [
        s.section for s in QuestionnaireResponse.query.filter_by(product_id=product_id, user_id=session['user_id']).distinct(QuestionnaireResponse.section)
    ]
    progress = [(i, s, (s in completed_sections)) for i, s in enumerate(sections)]
    return render_template(
        'fill_questionnaire_section.html',
        product=product,
        section_name=section_name,
        questions=questions,
        section_idx=section_idx,
        total_sections=len(sections),
        progress=progress
    )

@app.route('/product/<int:product_id>/results')
@login_required('client')
def product_results(product_id):
    resps = QuestionnaireResponse.query.filter_by(product_id=product_id, user_id=session['user_id']).all()
    return render_template('product_results.html', responses=resps)

@app.route('/review/<int:response_id>', methods=['GET', 'POST'])
@login_required('lead')
def review_questionnaire(response_id):
    resp = QuestionnaireResponse.query.get_or_404(response_id)
    if request.method == 'POST':
        comment = request.form['lead_comment']
        resp.comment = comment
        db.session.commit()
        flash('Review comment saved.')
        return redirect(url_for('dashboard'))
    return render_template('review_questionnaire.html', response=resp)

@app.route('/admin/product/<int:product_id>/details')
@login_required('superuser')
def admin_product_details(product_id):
    resps = QuestionnaireResponse.query.filter_by(product_id=product_id).all()
    return render_template('admin_product_details.html', responses=resps)

@app.route('/admin/products/delete/<int:product_id>')
@login_required('superuser')
def admin_delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    QuestionnaireResponse.query.filter_by(product_id=product_id).delete()
    db.session.delete(product)
    db.session.commit()
    flash('Product and all responses deleted.')
    return redirect(url_for('dashboard'))

@app.route('/api/product/<int:product_id>/scores')
@login_required()
def api_product_scores(product_id):
    resps = QuestionnaireResponse.query.filter_by(product_id=product_id).all()
    section_scores = {}
    section_counts = {}
    total_score = 0
    max_score = 0
    csv_map = {}
    with open('devweb.csv', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            q = row['Questions'].strip()
            opts = [o.strip() for o in row['Options'].split('\n') if o.strip()]
            scores = [int(s.strip()) if s.strip().isdigit() else 0 for s in row['Scores'].split('\n') if s.strip()]
            csv_map[q] = dict(zip(opts, scores))
            if scores: max_score += max(scores)
    for r in resps:
        sec = r.section
        if sec not in section_scores:
            section_scores[sec] = 0
            section_counts[sec] = 0
        score = csv_map.get(r.question, {}).get(r.answer, 0)
        section_scores[sec] += score
        section_counts[sec] += 1
        total_score += score
    section_labels = list(section_scores.keys())
    section_values = [section_scores[k] for k in section_labels]
    return jsonify({
        "section_labels": section_labels,
        "section_scores": section_values,
        "total_score": total_score,
        "max_score": max_score
    })

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(debug=True)