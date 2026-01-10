"""
WAGEPRO - Standalone Payroll Management System
Main Flask application
"""

from flask import Flask, jsonify, request, send_from_directory, render_template, make_response
from flask_cors import CORS
from functools import wraps
from datetime import datetime, date, timedelta
import jwt
import bcrypt
import re
from sqlalchemy import and_, or_, text, func

from app.database import Base, engine, SessionLocal
from app.models import (
    User, UserRole, Site, StaffMember, EmploymentType,
    PayPeriod, PayPeriodStatus, Payslip,
    Loan, LoanTransaction, Deduction,
    SavingsAccount, SavingsTransaction
)
from app.models.attendance import (
    WorkerAttendance, ProgressPicture, CheckInStatus, PictureStatus,
    LocationRequest, LocationRequestStatus,
    AttendanceReminder, ReminderType, ReminderStatus,
    LeaveRecord, LeaveType, LeaveStatus,
    NoWorkDay, NoWorkDayType, NoWorkAcknowledgment,
    StaffRewardPenalty, RewardPenaltyCategory, RewardPenaltySource, RewardPenaltyStatus,
    PointsConfiguration,
    SMSLog, SMSType
)
import secrets
from app.sms_notify import SMSNotifier
from app.sa_public_holidays import is_public_holiday, get_holiday_name
import os
import uuid
from math import radians, sin, cos, sqrt, atan2
from werkzeug.utils import secure_filename

# Create Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

# Configuration
app.config['SECRET_KEY'] = 'wagepro-secret-key-change-in-production'
app.config['TEMPLATES_AUTO_RELOAD'] = True  # Disable template caching
SECRET_KEY = app.config['SECRET_KEY']

# Create all database tables
Base.metadata.create_all(bind=engine)


# ===== SMS LOGGING HELPER =====

def log_sms(db, staff_id, phone_number, message, sms_type, batch_filename=None, sent_by_id=None, context=None):
    """
    Log an SMS message to the database for audit trail and history viewing.

    Args:
        db: Database session
        staff_id: Target staff member ID (or None)
        phone_number: Phone number the SMS was sent to
        message: SMS message content
        sms_type: SMSType enum value
        batch_filename: Optional batch file reference
        sent_by_id: ID of user who triggered the SMS (None for automated)
        context: Optional JSON context string
    """
    try:
        sms_log = SMSLog(
            staff_id=staff_id,
            phone_number=phone_number,
            message=message,
            sms_type=sms_type,
            batch_filename=batch_filename,
            sent_by_id=sent_by_id,
            context=context,
            status='sent'
        )
        db.add(sms_log)
        db.flush()  # Flush to ensure it's written
        print(f"[SMS LOG] Logged SMS to {phone_number} (staff_id={staff_id})")
    except Exception as e:
        print(f"[SMS LOG ERROR] Failed to log SMS: {e}")
        import traceback
        traceback.print_exc()


# ===== AUTHENTICATION DECORATOR =====

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            db = SessionLocal()
            current_user = db.query(User).filter(User.id == data['user_id']).first()

            if not current_user:
                db.close()
                return jsonify({'error': 'User not found'}), 401

            # Eagerly load site info before closing session
            if current_user.site_id:
                _ = current_user.site  # Force load the relationship

            db.close()

            return f(current_user=current_user, *args, **kwargs)

        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

    return decorated


def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.role != UserRole.ADMIN:
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user=current_user, *args, **kwargs)
    return decorated


def manager_or_admin_required(f):
    """Decorator to require manager or admin role"""
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.role not in [UserRole.ADMIN, UserRole.MANAGER]:
            return jsonify({'error': 'Manager or Admin access required'}), 403
        return f(current_user=current_user, *args, **kwargs)
    return decorated


# ===== ROUTES =====

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({'status': 'ok', 'service': 'wagepro'}), 200


@app.route('/init-admin')
def init_admin():
    """Create admin user if not exists - for initial Railway setup"""
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == 'admin').first()
        if admin:
            return jsonify({'message': 'Admin already exists', 'username': 'admin'}), 200

        password = "admin123"
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        admin = User(
            username='admin',
            password_hash=password_hash,
            full_name='System Administrator',
            email='admin@wagepro.local',
            role=UserRole.ADMIN,
            is_active=True
        )
        db.add(admin)
        db.commit()
        return jsonify({'message': 'Admin created', 'username': 'admin', 'password': 'admin123'}), 201
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/')
def index():
    """Serve main page"""
    response = send_from_directory('templates', 'index.html')
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/manager')
def manager_portal():
    """Serve manager portal page"""
    return send_from_directory('templates', 'manager.html')


@app.route('/mobile')
def mobile_portal():
    """Serve mobile manager portal for daily work entry"""
    return send_from_directory('templates', 'mobile.html')


@app.route('/workpro')
def workpro_mobile():
    """Mobile WORKPRO interface for managers - projects, tasks, shopping list"""
    return send_from_directory('templates', 'workpro_mobile.html')


@app.route('/static/<path:path>')
def send_static(path):
    """Serve static files"""
    return send_from_directory('static', path)


# ===== AUTHENTICATION =====

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login"""
    db = SessionLocal()
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        user = db.query(User).filter(User.username == username).first()

        if not user or not user.is_active:
            return jsonify({'error': 'Invalid credentials'}), 401

        # Check password
        if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            return jsonify({'error': 'Invalid credentials'}), 401

        # Update last login
        user.last_login = datetime.utcnow()
        db.commit()

        # Generate JWT token
        token = jwt.encode({
            'user_id': user.id,
            'username': user.username,
            'role': user.role.value
        }, SECRET_KEY, algorithm='HS256')

        return jsonify({
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'full_name': user.full_name,
                'role': user.role.value
            }
        })

    finally:
        db.close()


@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    """Get current user info"""
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'full_name': current_user.full_name,
        'email': current_user.email,
        'role': current_user.role.value,
        'site_id': current_user.site_id,
        'site_name': current_user.site.name if current_user.site else None
    })


@app.route('/api/auth/verify-password', methods=['POST'])
@token_required
@admin_required
def verify_password(current_user):
    """
    Verify admin password for sensitive operations
    Admin-only endpoint for re-authentication
    """
    db = SessionLocal()
    try:
        data = request.json
        password = data.get('password')

        if not password:
            return jsonify({'error': 'Password required'}), 400

        # Verify password matches current admin user
        if not bcrypt.checkpw(password.encode('utf-8'), current_user.password_hash.encode('utf-8')):
            return jsonify({'error': 'Invalid password'}), 401

        return jsonify({'verified': True})

    finally:
        db.close()


# ===== USER MANAGEMENT =====

@app.route('/api/users', methods=['GET'])
@token_required
@admin_required
def get_users(current_user):
    """Get all users (admin only)"""
    db = SessionLocal()
    try:
        users = db.query(User).all()
        return jsonify([{
            'id': u.id,
            'username': u.username,
            'full_name': u.full_name,
            'email': u.email,
            'role': u.role.value,
            'is_active': u.is_active,
            'created_at': u.created_at.isoformat() if u.created_at else None,
            'last_login': u.last_login.isoformat() if u.last_login else None
        } for u in users])
    finally:
        db.close()


@app.route('/api/users', methods=['POST'])
@token_required
@admin_required
def create_user(current_user):
    """Create new user (admin only)"""
    db = SessionLocal()
    try:
        data = request.json

        # Validate required fields
        if not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username and password are required'}), 400

        # Check if username already exists
        existing = db.query(User).filter(User.username == data['username']).first()
        if existing:
            return jsonify({'error': 'Username already exists'}), 400

        # Check if email already exists (if provided)
        if data.get('email'):
            existing_email = db.query(User).filter(User.email == data['email']).first()
            if existing_email:
                return jsonify({'error': 'Email already exists'}), 400

        # Hash password
        password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Create user
        user = User(
            username=data['username'],
            password_hash=password_hash,
            full_name=data.get('full_name', data['username']),
            email=data.get('email'),
            role=UserRole(data.get('role', 'viewer')),
            is_active=data.get('is_active', True)
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return jsonify({
            'id': user.id,
            'username': user.username,
            'message': 'User created successfully'
        }), 201

    finally:
        db.close()


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@token_required
@admin_required
def update_user(current_user, user_id):
    """Update user (admin only)"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        data = request.json

        # Update username if provided and different
        if data.get('username') and data['username'] != user.username:
            existing = db.query(User).filter(User.username == data['username']).first()
            if existing:
                return jsonify({'error': 'Username already exists'}), 400
            user.username = data['username']

        # Update email if provided and different
        if 'email' in data and data['email'] != user.email:
            if data['email']:
                existing_email = db.query(User).filter(
                    User.email == data['email'],
                    User.id != user_id
                ).first()
                if existing_email:
                    return jsonify({'error': 'Email already exists'}), 400
            user.email = data['email']

        # Update other fields
        if data.get('full_name'):
            user.full_name = data['full_name']

        if data.get('role'):
            user.role = UserRole(data['role'])

        db.commit()
        db.refresh(user)

        return jsonify({
            'id': user.id,
            'username': user.username,
            'message': 'User updated successfully'
        })

    finally:
        db.close()


@app.route('/api/users/<int:user_id>/change-password', methods=['POST'])
@token_required
def change_password(current_user, user_id):
    """Change user password (admin can change any, users can change own)"""
    db = SessionLocal()
    try:
        # Only admin can change other users' passwords
        if user_id != current_user.id and current_user.role != UserRole.ADMIN:
            return jsonify({'error': 'Access denied'}), 403

        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        data = request.json
        new_password = data.get('new_password')

        if not new_password:
            return jsonify({'error': 'New password is required'}), 400

        if len(new_password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        # If non-admin user is changing their own password, require old password
        # Admins can change any password (including their own) without old password
        if user_id == current_user.id and current_user.role != UserRole.ADMIN:
            old_password = data.get('old_password')
            if not old_password:
                return jsonify({'error': 'Old password is required'}), 400

            if not bcrypt.checkpw(old_password.encode('utf-8'), user.password_hash.encode('utf-8')):
                return jsonify({'error': 'Old password is incorrect'}), 400

        # Hash new password
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.password_hash = password_hash

        db.commit()

        return jsonify({'message': 'Password changed successfully'})

    finally:
        db.close()


@app.route('/api/users/<int:user_id>/toggle-active', methods=['POST'])
@token_required
@admin_required
def toggle_user_active(current_user, user_id):
    """Toggle user active/inactive status (admin only)"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Prevent deactivating yourself
        if user.id == current_user.id:
            return jsonify({'error': 'Cannot deactivate your own account'}), 400

        user.is_active = not user.is_active
        db.commit()

        status = 'activated' if user.is_active else 'deactivated'

        return jsonify({
            'id': user.id,
            'is_active': user.is_active,
            'message': f'User {status} successfully'
        })

    finally:
        db.close()


# ===== SITES =====

@app.route('/api/sites', methods=['GET'])
@token_required
def get_sites(current_user):
    """Get all sites"""
    db = SessionLocal()
    try:
        # Get all sites, or filter by active_only parameter
        active_only = request.args.get('active_only', 'false').lower() == 'true'

        if active_only:
            sites = db.query(Site).filter(Site.is_active == True).all()
        else:
            sites = db.query(Site).all()

        result = []
        for s in sites:
            standby_staff = None
            if getattr(s, 'standby_staff_id', None):
                staff = db.query(StaffMember).get(s.standby_staff_id)
                if staff:
                    standby_staff = {'id': staff.id, 'name': staff.full_name}
            result.append({
                'id': s.id,
                'name': s.name,
                'code': s.code,
                'description': s.description,
                'address': s.address,
                'bank_name': s.bank_name,
                'account_number': s.account_number,
                'is_active': s.is_active,
                'gps_latitude': s.gps_latitude,
                'gps_longitude': s.gps_longitude,
                'gps_radius_meters': s.gps_radius_meters,
                'standby_staff_id': getattr(s, 'standby_staff_id', None),
                'standby_staff': standby_staff
            })
        return jsonify(result)
    finally:
        db.close()


@app.route('/api/sites', methods=['POST'])
@token_required
@manager_or_admin_required
def create_site(current_user):
    """Create new site"""
    db = SessionLocal()
    try:
        data = request.json

        site = Site(
            name=data['name'],
            code=data.get('code'),
            description=data.get('description'),
            address=data.get('address'),
            bank_name=data.get('bank_name'),
            account_number=data.get('account_number')
        )

        db.add(site)
        db.commit()
        db.refresh(site)

        return jsonify({
            'id': site.id,
            'name': site.name,
            'code': site.code,
            'message': 'Site created successfully'
        }), 201

    finally:
        db.close()


@app.route('/api/sites/<int:site_id>', methods=['PUT'])
@token_required
@manager_or_admin_required
def update_site(current_user, site_id):
    """Update site"""
    db = SessionLocal()
    try:
        site = db.query(Site).filter(Site.id == site_id).first()

        if not site:
            return jsonify({'error': 'Site not found'}), 404

        data = request.json

        # Update fields
        if data.get('name'):
            site.name = data['name']
        if 'code' in data:
            site.code = data['code']
        if 'description' in data:
            site.description = data['description']
        if 'address' in data:
            site.address = data['address']
        if 'bank_name' in data:
            site.bank_name = data['bank_name']
        if 'account_number' in data:
            site.account_number = data['account_number']
        if 'gps_latitude' in data:
            site.gps_latitude = data['gps_latitude']
        if 'gps_longitude' in data:
            site.gps_longitude = data['gps_longitude']
        if 'gps_radius_meters' in data:
            site.gps_radius_meters = data['gps_radius_meters']

        db.commit()
        db.refresh(site)

        return jsonify({
            'id': site.id,
            'name': site.name,
            'message': 'Site updated successfully'
        })

    finally:
        db.close()


@app.route('/api/sites/<int:site_id>/toggle-active', methods=['POST'])
@token_required
@manager_or_admin_required
def toggle_site_active(current_user, site_id):
    """Toggle site active/inactive status"""
    db = SessionLocal()
    try:
        site = db.query(Site).filter(Site.id == site_id).first()

        if not site:
            return jsonify({'error': 'Site not found'}), 404

        site.is_active = not site.is_active
        db.commit()

        status = 'activated' if site.is_active else 'deactivated'

        return jsonify({
            'id': site.id,
            'is_active': site.is_active,
            'message': f'Site {status} successfully'
        })

    finally:
        db.close()


# ===== STAFF =====

@app.route('/api/staff', methods=['GET'])
@token_required
def get_staff(current_user):
    """Get all staff members"""
    db = SessionLocal()
    try:
        query = db.query(StaffMember)

        # Filter by site if provided
        site_id = request.args.get('site_id')
        if site_id:
            query = query.filter(StaffMember.site_id == int(site_id))

        # Filter by active status
        active_only = request.args.get('active_only', 'true').lower() == 'true'
        if active_only:
            query = query.filter(StaffMember.is_active == True)

        staff = query.all()

        return jsonify([{
            'id': s.id,
            'first_name': s.first_name,
            'last_name': s.last_name,
            'full_name': s.full_name,
            'id_number': s.id_number,
            'email': s.email,
            'phone': s.phone,
            'mobile': s.mobile,
            'site_id': s.site_id,
            'site_name': s.site.name if s.site else None,
            'employment_type': s.employment_type.value,
            'position': s.position,
            'department': s.department,
            'hire_date': s.hire_date.isoformat() if s.hire_date else None,
            'hourly_rate': s.hourly_rate,
            'daily_rate': s.daily_rate,
            'max_loan_amount': s.max_loan_amount,
            'bank_name': s.bank_name,
            'bank_account': s.bank_account,
            'is_active': s.is_active,
            'face_enrolled': s.face_descriptor is not None,
            'face_enrolled_at': s.face_enrolled_at.isoformat() if s.face_enrolled_at else None,
            'gps_exempt': s.gps_exempt
        } for s in staff])
    finally:
        db.close()


@app.route('/api/staff', methods=['POST'])
@token_required
@manager_or_admin_required
def create_staff(current_user):
    """Create new staff member"""
    db = SessionLocal()
    try:
        data = request.json

        # Validate daily rate - must be > 0
        daily_rate = float(data.get('daily_rate', 0))
        if daily_rate <= 0:
            return jsonify({'error': 'Daily rate must be greater than R0.00'}), 400

        staff = StaffMember(
            first_name=data['first_name'],
            last_name=data['last_name'],
            id_number=data.get('id_number'),
            email=data.get('email'),
            phone=data.get('phone'),
            mobile=data.get('mobile'),
            address=data.get('address'),
            emergency_contact_name=data.get('emergency_contact_name'),
            emergency_contact_phone=data.get('emergency_contact_phone'),
            site_id=data.get('site_id'),
            employment_type=data.get('employment_type', 'casual'),
            position=data.get('position'),
            department=data.get('department'),
            hire_date=datetime.fromisoformat(data['hire_date']).date() if data.get('hire_date') else None,
            hourly_rate=float(data.get('hourly_rate', 0)),
            daily_rate=float(data.get('daily_rate', 0)),
            max_loan_amount=float(data.get('max_loan_amount', 0)),
            bank_name=data.get('bank_name'),
            bank_account=data.get('bank_account'),
            tax_number=data.get('tax_number'),
            notes=data.get('notes')
        )

        db.add(staff)
        db.commit()
        db.refresh(staff)

        return jsonify({
            'id': staff.id,
            'full_name': staff.full_name,
            'message': 'Staff member created successfully'
        }), 201

    finally:
        db.close()


@app.route('/api/staff/<int:staff_id>', methods=['PUT'])
@token_required
@manager_or_admin_required
def update_staff(current_user, staff_id):
    """Update staff member"""
    db = SessionLocal()
    try:
        staff = db.query(StaffMember).filter(StaffMember.id == staff_id).first()
        if not staff:
            return jsonify({'error': 'Staff member not found'}), 404

        data = request.json

        # Update fields
        staff.first_name = data.get('first_name', staff.first_name)
        staff.last_name = data.get('last_name', staff.last_name)
        staff.id_number = data.get('id_number', staff.id_number)
        staff.email = data.get('email', staff.email)
        staff.phone = data.get('phone', staff.phone)
        staff.mobile = data.get('mobile', staff.mobile)
        staff.address = data.get('address', staff.address)
        staff.site_id = data.get('site_id', staff.site_id)
        staff.employment_type = data.get('employment_type', staff.employment_type)
        staff.position = data.get('position', staff.position)
        staff.department = data.get('department', staff.department)
        staff.bank_name = data.get('bank_name', staff.bank_name)
        staff.bank_account = data.get('bank_account', staff.bank_account)

        # Get employment type (may be updated in this request)
        emp_type = data.get('employment_type', staff.employment_type)
        is_admin = emp_type == 'admin'

        if data.get('hourly_rate') is not None and data.get('hourly_rate') != '':
            staff.hourly_rate = float(data['hourly_rate'])
        if data.get('daily_rate') is not None and data.get('daily_rate') != '':
            new_daily_rate = float(data['daily_rate'])
            # Skip rate validation for admin staff
            if new_daily_rate <= 0 and not is_admin:
                return jsonify({'error': 'Daily rate must be greater than R0.00'}), 400
            staff.daily_rate = new_daily_rate
        if data.get('max_loan_amount') is not None and data.get('max_loan_amount') != '':
            staff.max_loan_amount = float(data['max_loan_amount'])

        # Handle is_active toggle
        if 'is_active' in data:
            staff.is_active = data['is_active']

        db.commit()

        return jsonify({'message': 'Staff member updated successfully'})

    finally:
        db.close()


# ===== PAY PERIODS =====

@app.route('/api/pay-periods', methods=['GET'])
@token_required
def get_pay_periods(current_user):
    """Get all pay periods"""
    db = SessionLocal()
    try:
        periods = db.query(PayPeriod).order_by(PayPeriod.start_date.desc()).all()
        return jsonify([{
            'id': p.id,
            'period_number': p.period_number,
            'year': p.year,
            'start_date': p.start_date.isoformat(),
            'end_date': p.end_date.isoformat(),
            'status': p.status.value,
            'total_gross_pay': p.total_gross_pay,
            'total_net_pay': p.total_net_pay,
            'created_at': p.created_at.isoformat() if p.created_at else None
        } for p in periods])
    finally:
        db.close()


@app.route('/api/pay-periods', methods=['POST'])
@token_required
@manager_or_admin_required
def create_pay_period(current_user):
    """Create new pay period"""
    db = SessionLocal()
    try:
        data = request.json

        # Calculate period number
        year = data['year']
        existing_count = db.query(PayPeriod).filter(PayPeriod.year == year).count()
        period_number = existing_count + 1

        period = PayPeriod(
            period_number=period_number,
            year=year,
            start_date=datetime.fromisoformat(data['start_date']).date(),
            end_date=datetime.fromisoformat(data['end_date']).date(),
            status=PayPeriodStatus.OPEN
        )

        db.add(period)
        db.commit()
        db.refresh(period)

        return jsonify({
            'id': period.id,
            'period_number': period.period_number,
            'message': 'Pay period created successfully'
        }), 201

    finally:
        db.close()


@app.route('/api/pay-periods/<int:period_id>', methods=['DELETE'])
@token_required
@manager_or_admin_required
def delete_pay_period(current_user, period_id):
    """
    Delete a pay period and all associated payslips

    Query parameters:
    - force: Set to 'true' to force delete locked periods (Admin only)

    Without force:
    - Only allowed if no PDFs have been generated (period not locked)

    With force=true:
    - Admin-only access
    - Deletes period AND all PDF files
    - Requires password verification before calling this endpoint
    """
    import os
    import shutil

    db = SessionLocal()
    try:
        # Get force parameter
        force_delete = request.args.get('force', 'false').lower() == 'true'

        period = db.query(PayPeriod).filter(PayPeriod.id == period_id).first()
        if not period:
            return jsonify({'error': 'Pay period not found'}), 404

        # Check if PDFs exist for this period (locked status)
        period_folder = f"{period.year}-Period-{period.period_number}"
        pdf_dir = os.path.join('c:\\wagepro\\payslips', period_folder)
        has_pdfs = os.path.exists(pdf_dir) and os.listdir(pdf_dir)

        # Handle locked period
        if has_pdfs:
            if not force_delete:
                # Return locked status - frontend will handle force delete flow
                return jsonify({
                    'error': 'Cannot delete: Period is locked. PDFs have been generated.',
                    'locked': True,
                    'pdf_count': len(os.listdir(pdf_dir)) if os.path.exists(pdf_dir) else 0
                }), 403

            # Force delete - admin only
            if current_user.role != UserRole.ADMIN:
                return jsonify({
                    'error': 'Force delete requires Admin privileges'
                }), 403

            # Delete PDF directory and all files
            try:
                shutil.rmtree(pdf_dir)
            except Exception as e:
                return jsonify({
                    'error': f'Failed to delete PDF files: {str(e)}'
                }), 500

        # Delete all payslips for this period
        db.query(Payslip).filter(Payslip.pay_period_id == period_id).delete()

        # Delete the period
        db.delete(period)
        db.commit()

        return jsonify({
            'message': f'Pay period {period.year}-{period.period_number} deleted successfully',
            'forced': force_delete,
            'pdfs_deleted': has_pdfs
        })

    finally:
        db.close()


# ===== PAYSLIPS =====

@app.route('/api/payslips', methods=['GET'])
@token_required
def get_payslips(current_user):
    """Get payslips for a pay period"""
    db = SessionLocal()
    try:
        pay_period_id = request.args.get('pay_period_id')

        if not pay_period_id:
            return jsonify({'error': 'pay_period_id required'}), 400

        payslips = db.query(Payslip).filter(
            Payslip.pay_period_id == int(pay_period_id)
        ).all()

        result = []
        for p in payslips:
            # Skip payslips for deleted staff
            if not p.staff:
                continue

            # Calculate per-week multipliers (handle None values)
            w1_weekdays = sum([p.w1_monday or 0, p.w1_tuesday or 0, p.w1_wednesday or 0, p.w1_thursday or 0, p.w1_friday or 0])
            w2_weekdays = sum([p.w2_monday or 0, p.w2_tuesday or 0, p.w2_wednesday or 0, p.w2_thursday or 0, p.w2_friday or 0])

            w1_weekend_multiplier = 1.5 if w1_weekdays >= 3 else 1.0
            w2_weekend_multiplier = 1.5 if w2_weekdays >= 3 else 1.0

            # Calculate savings deduction (FLOAT/SAVINGS) vs other deductions
            savings_deduction = 0.0
            pure_other_deductions = 0.0
            active_deductions = db.query(Deduction).filter(
                and_(
                    Deduction.staff_id == p.staff_id,
                    Deduction.is_active == True
                )
            ).all()
            for ded in active_deductions:
                ded_amount = ded.calculate_deduction(p.gross_pay)
                if ded.description.upper() in ['FLOAT', 'SAVINGS', 'SAVE']:
                    savings_deduction += ded_amount
                else:
                    pure_other_deductions += ded_amount

            # Get active loans for this staff member
            from app.models import Loan
            active_loans = db.query(Loan).filter(
                and_(
                    Loan.staff_id == p.staff_id,
                    Loan.is_active == True,
                    Loan.is_completed == False
                )
            ).all()
            loan_deduction = sum((loan.installment_amount or 0) for loan in active_loans)

            # Auto-recalculate if not approved
            if not p.is_approved:
                total_other = savings_deduction + pure_other_deductions
                total_deductions = loan_deduction + total_other
                net_pay = p.gross_pay - total_deductions

                # Update payslip in database
                p.loan_deduction = loan_deduction
                p.other_deductions = total_other
                p.total_deductions = total_deductions
                p.net_pay = net_pay
                db.commit()
            else:
                # Use stored values for approved payslips
                loan_deduction = p.loan_deduction
                total_deductions = p.total_deductions
                net_pay = p.net_pay

            # Get employment type safely
            try:
                emp_type = p.staff.employment_type.value if p.staff.employment_type else 'casual'
            except:
                emp_type = 'casual'

            result.append({
                'id': p.id,
                'pay_period_id': p.pay_period_id,
                'staff_id': p.staff_id,
                'staff_name': p.staff.full_name,
                'staff_position': p.staff.position,
                'staff_employment_type': emp_type,
                'staff_daily_rate': p.staff.daily_rate or 0,
                'staff_site_name': p.staff.site.name if p.staff.site else None,
                'w1_monday': p.w1_monday,
                'w1_tuesday': p.w1_tuesday,
                'w1_wednesday': p.w1_wednesday,
                'w1_thursday': p.w1_thursday,
                'w1_friday': p.w1_friday,
                'w1_saturday': p.w1_saturday,
                'w1_sunday': p.w1_sunday,
                'w2_monday': p.w2_monday,
                'w2_tuesday': p.w2_tuesday,
                'w2_wednesday': p.w2_wednesday,
                'w2_thursday': p.w2_thursday,
                'w2_friday': p.w2_friday,
                'w2_saturday': p.w2_saturday,
                'w2_sunday': p.w2_sunday,
                'w1_weekend_multiplier': w1_weekend_multiplier,
                'w2_weekend_multiplier': w2_weekend_multiplier,
                'hourly_rate': p.hourly_rate,
                'daily_rate': p.daily_rate,
                'total_hours': p.total_hours,
                'weekday_pay': p.weekday_pay,
                'weekend_pay': p.weekend_pay,
                'overtime_hours': p.overtime_hours,
                'overtime_pay': p.overtime_pay,
                'bonus': p.bonus,
                'gross_pay': p.gross_pay,
                'loan_deduction': loan_deduction,
                'savings_deduction': savings_deduction,
                'other_deductions': pure_other_deductions,
                'total_deductions': total_deductions,
                'net_pay': net_pay,
                'is_verified': p.is_verified,
                'is_approved': p.is_approved,
                'is_paid': p.is_paid,
                'payment_method': p.payment_method,
                'notes': p.notes
            })

        return jsonify(result)

    finally:
        db.close()


@app.route('/api/payslips', methods=['POST'])
@token_required
@manager_or_admin_required
def create_payslip(current_user):
    """Create or update payslip with wage calculation"""
    db = SessionLocal()
    try:
        data = request.json

        # Get staff member
        staff = db.query(StaffMember).filter(StaffMember.id == data['staff_id']).first()
        if not staff:
            return jsonify({'error': 'Staff member not found'}), 400

        # Check if payslip already exists
        existing = db.query(Payslip).filter(
            and_(
                Payslip.staff_id == data['staff_id'],
                Payslip.pay_period_id == data['pay_period_id']
            )
        ).first()

        if existing:
            return jsonify({
                'error': f'Payslip already exists for {staff.full_name}',
                'existing_id': existing.id
            }), 409

        # WAGE CALCULATION
        daily_rate = staff.daily_rate if staff.daily_rate else 0.0
        hourly_rate = staff.hourly_rate if staff.hourly_rate else (daily_rate / 8.0 if daily_rate > 0 else 0.0)

        # Per-week calculation
        w1_weekdays = sum([
            data.get('w1_monday', False),
            data.get('w1_tuesday', False),
            data.get('w1_wednesday', False),
            data.get('w1_thursday', False),
            data.get('w1_friday', False)
        ])
        w1_weekends = sum([
            data.get('w1_saturday', False),
            data.get('w1_sunday', False)
        ])
        w1_weekend_multiplier = 1.5 if w1_weekdays >= 3 else 1.0

        w2_weekdays = sum([
            data.get('w2_monday', False),
            data.get('w2_tuesday', False),
            data.get('w2_wednesday', False),
            data.get('w2_thursday', False),
            data.get('w2_friday', False)
        ])
        w2_weekends = sum([
            data.get('w2_saturday', False),
            data.get('w2_sunday', False)
        ])
        w2_weekend_multiplier = 1.5 if w2_weekdays >= 3 else 1.0

        # Calculate pay
        weekdays_worked = w1_weekdays + w2_weekdays
        weekends_worked = w1_weekends + w2_weekends

        STANDARD_HOURS_PER_DAY = 8.0
        weekday_hours = weekdays_worked * STANDARD_HOURS_PER_DAY
        weekend_hours = weekends_worked * STANDARD_HOURS_PER_DAY
        total_hours = weekday_hours + weekend_hours

        if daily_rate > 0:
            weekday_pay = weekdays_worked * daily_rate
            w1_weekend_pay = w1_weekends * daily_rate * w1_weekend_multiplier
            w2_weekend_pay = w2_weekends * daily_rate * w2_weekend_multiplier
            weekend_pay = w1_weekend_pay + w2_weekend_pay
        else:
            weekday_pay = weekday_hours * hourly_rate
            w1_weekend_hours = w1_weekends * STANDARD_HOURS_PER_DAY
            w2_weekend_hours = w2_weekends * STANDARD_HOURS_PER_DAY
            w1_weekend_pay = w1_weekend_hours * hourly_rate * w1_weekend_multiplier
            w2_weekend_pay = w2_weekend_hours * hourly_rate * w2_weekend_multiplier
            weekend_pay = w1_weekend_pay + w2_weekend_pay

        overtime_hours = data.get('overtime_hours', 0.0)
        overtime_pay = overtime_hours * hourly_rate * 1.5

        bonus = data.get('bonus', 0.0)
        gross_pay = weekday_pay + weekend_pay + overtime_pay + bonus

        # Get deductions
        active_loans = db.query(Loan).filter(
            and_(
                Loan.staff_id == data['staff_id'],
                Loan.is_active == True,
                Loan.is_completed == False
            )
        ).all()
        loan_deduction = sum((loan.installment_amount or 0) for loan in active_loans)

        active_deductions = db.query(Deduction).filter(
            and_(
                Deduction.staff_id == data['staff_id'],
                Deduction.is_active == True
            )
        ).all()

        other_deductions = 0.0
        for deduction in active_deductions:
            other_deductions += deduction.calculate_deduction(gross_pay)

        total_deductions = loan_deduction + other_deductions
        net_pay = gross_pay - total_deductions

        # Create payslip
        payslip = Payslip(
            pay_period_id=data['pay_period_id'],
            staff_id=data['staff_id'],
            w1_monday=data.get('w1_monday', False),
            w1_tuesday=data.get('w1_tuesday', False),
            w1_wednesday=data.get('w1_wednesday', False),
            w1_thursday=data.get('w1_thursday', False),
            w1_friday=data.get('w1_friday', False),
            w1_saturday=data.get('w1_saturday', False),
            w1_sunday=data.get('w1_sunday', False),
            w2_monday=data.get('w2_monday', False),
            w2_tuesday=data.get('w2_tuesday', False),
            w2_wednesday=data.get('w2_wednesday', False),
            w2_thursday=data.get('w2_thursday', False),
            w2_friday=data.get('w2_friday', False),
            w2_saturday=data.get('w2_saturday', False),
            w2_sunday=data.get('w2_sunday', False),
            total_hours=total_hours,
            weekday_hours=weekday_hours,
            weekend_hours=weekend_hours,
            hourly_rate=hourly_rate,
            daily_rate=daily_rate,
            weekday_pay=weekday_pay,
            weekend_pay=weekend_pay,
            overtime_hours=overtime_hours,
            overtime_pay=overtime_pay,
            bonus=bonus,
            gross_pay=gross_pay,
            loan_deduction=loan_deduction,
            other_deductions=other_deductions,
            total_deductions=total_deductions,
            net_pay=net_pay,
            notes=data.get('notes'),
            created_by_id=current_user.id
        )

        db.add(payslip)
        db.commit()
        db.refresh(payslip)

        return jsonify({
            'id': payslip.id,
            'message': 'Payslip created successfully',
            'net_pay': net_pay
        }), 201

    finally:
        db.close()


@app.route('/api/payslips/<int:payslip_id>', methods=['PUT'])
@token_required
@manager_or_admin_required
def update_payslip(current_user, payslip_id):
    """Update payslip and recalculate"""
    print(f"\n{'='*70}")
    print(f"UPDATE PAYSLIP CALLED - ID: {payslip_id}")
    print(f"{'='*70}")

    db = SessionLocal()
    try:
        payslip = db.query(Payslip).filter(Payslip.id == payslip_id).first()
        if not payslip:
            return jsonify({'error': 'Payslip not found'}), 404

        data = request.json
        staff = payslip.staff

        print(f"Staff: {staff.full_name}")
        print(f"Received data keys: {list(data.keys())}")
        print(f"Days in request: w1_mon={data.get('w1_monday')}, w1_tue={data.get('w1_tuesday')}, ...")
        print(f"Current daily_rate: R {payslip.daily_rate}")
        print(f"{'='*70}\n")

        # Update days worked
        payslip.w1_monday = data.get('w1_monday', payslip.w1_monday)
        payslip.w1_tuesday = data.get('w1_tuesday', payslip.w1_tuesday)
        payslip.w1_wednesday = data.get('w1_wednesday', payslip.w1_wednesday)
        payslip.w1_thursday = data.get('w1_thursday', payslip.w1_thursday)
        payslip.w1_friday = data.get('w1_friday', payslip.w1_friday)
        payslip.w1_saturday = data.get('w1_saturday', payslip.w1_saturday)
        payslip.w1_sunday = data.get('w1_sunday', payslip.w1_sunday)
        payslip.w2_monday = data.get('w2_monday', payslip.w2_monday)
        payslip.w2_tuesday = data.get('w2_tuesday', payslip.w2_tuesday)
        payslip.w2_wednesday = data.get('w2_wednesday', payslip.w2_wednesday)
        payslip.w2_thursday = data.get('w2_thursday', payslip.w2_thursday)
        payslip.w2_friday = data.get('w2_friday', payslip.w2_friday)
        payslip.w2_saturday = data.get('w2_saturday', payslip.w2_saturday)
        payslip.w2_sunday = data.get('w2_sunday', payslip.w2_sunday)

        if 'overtime_hours' in data:
            payslip.overtime_hours = float(data['overtime_hours'])
        if 'bonus' in data:
            payslip.bonus = float(data['bonus'])
        if 'payment_method' in data:
            payslip.payment_method = data['payment_method']

        # RECALCULATE - Always use CURRENT staff rate (in case it was updated)
        # Update payslip with current staff rates
        payslip.daily_rate = staff.daily_rate or 0.0
        payslip.hourly_rate = staff.hourly_rate or 0.0
        daily_rate = payslip.daily_rate
        hourly_rate = payslip.hourly_rate

        w1_weekdays = sum([payslip.w1_monday, payslip.w1_tuesday, payslip.w1_wednesday,
                          payslip.w1_thursday, payslip.w1_friday])
        w1_weekends = sum([payslip.w1_saturday, payslip.w1_sunday])
        w1_weekend_multiplier = 1.5 if w1_weekdays >= 3 else 1.0

        w2_weekdays = sum([payslip.w2_monday, payslip.w2_tuesday, payslip.w2_wednesday,
                          payslip.w2_thursday, payslip.w2_friday])
        w2_weekends = sum([payslip.w2_saturday, payslip.w2_sunday])
        w2_weekend_multiplier = 1.5 if w2_weekdays >= 3 else 1.0

        weekdays_worked = w1_weekdays + w2_weekdays
        weekends_worked = w1_weekends + w2_weekends

        STANDARD_HOURS_PER_DAY = 8.0
        weekday_hours = weekdays_worked * STANDARD_HOURS_PER_DAY
        weekend_hours = weekends_worked * STANDARD_HOURS_PER_DAY
        total_hours = weekday_hours + weekend_hours

        if daily_rate > 0:
            weekday_pay = weekdays_worked * daily_rate
            w1_weekend_pay = w1_weekends * daily_rate * w1_weekend_multiplier
            w2_weekend_pay = w2_weekends * daily_rate * w2_weekend_multiplier
            weekend_pay = w1_weekend_pay + w2_weekend_pay
        else:
            weekday_pay = weekday_hours * hourly_rate
            w1_weekend_hours = w1_weekends * STANDARD_HOURS_PER_DAY
            w2_weekend_hours = w2_weekends * STANDARD_HOURS_PER_DAY
            w1_weekend_pay = w1_weekend_hours * hourly_rate * w1_weekend_multiplier
            w2_weekend_pay = w2_weekend_hours * hourly_rate * w2_weekend_multiplier
            weekend_pay = w1_weekend_pay + w2_weekend_pay

        overtime_pay = payslip.overtime_hours * hourly_rate * 1.5
        gross_pay = weekday_pay + weekend_pay + overtime_pay + payslip.bonus

        # DEBUG: Print calculation breakdown
        print("\n" + "="*70)
        print(f"CALCULATION DEBUG - Payslip ID: {payslip_id}, Staff: {staff.full_name}")
        print("="*70)
        print(f"Daily Rate: R {daily_rate:.2f}")
        print(f"Week 1 - Weekdays: {w1_weekdays}, Weekends: {w1_weekends}, Weekend Multiplier: {w1_weekend_multiplier}x")
        print(f"Week 2 - Weekdays: {w2_weekdays}, Weekends: {w2_weekends}, Weekend Multiplier: {w2_weekend_multiplier}x")
        print(f"Total - Weekdays: {weekdays_worked}, Weekends: {weekends_worked}")
        print(f"Weekday Pay: R {weekday_pay:.2f} ({weekdays_worked} x R {daily_rate:.2f})")
        print(f"W1 Weekend Pay: R {w1_weekend_pay:.2f} ({w1_weekends} x R {daily_rate:.2f} x {w1_weekend_multiplier})")
        print(f"W2 Weekend Pay: R {w2_weekend_pay:.2f} ({w2_weekends} x R {daily_rate:.2f} x {w2_weekend_multiplier})")
        print(f"Total Weekend Pay: R {weekend_pay:.2f}")
        print(f"Overtime Pay: R {overtime_pay:.2f}")
        print(f"Bonus: R {payslip.bonus:.2f}")
        print(f"GROSS PAY: R {gross_pay:.2f}")
        print("="*70 + "\n")

        # Recalculate deductions
        active_loans = db.query(Loan).filter(
            and_(
                Loan.staff_id == staff.id,
                Loan.is_active == True,
                Loan.is_completed == False
            )
        ).all()
        loan_deduction = sum((loan.installment_amount or 0) for loan in active_loans)

        active_deductions = db.query(Deduction).filter(
            and_(
                Deduction.staff_id == staff.id,
                Deduction.is_active == True
            )
        ).all()

        other_deductions = 0.0
        for deduction in active_deductions:
            other_deductions += deduction.calculate_deduction(gross_pay)

        # Calculate rewards/penalties for this payslip
        # FAIR SYSTEM: 10 points = 1 hour of individual's current pay rate
        reward_points = 0
        penalty_points = 0
        reward_adjustment = 0.0
        penalty_adjustment = 0.0

        try:
            # Get approved rewards/penalties for this staff and pay period
            approved_items = db.query(StaffRewardPenalty).filter(
                StaffRewardPenalty.pay_period_id == payslip.pay_period_id,
                StaffRewardPenalty.staff_id == staff.id,
                StaffRewardPenalty.status == RewardPenaltyStatus.APPROVED
            ).all()

            # Calculate point value based on staff's hourly rate
            # 10 points = 1 hour, so 1 point = hourly_rate / 10
            hourly_rate = staff.hourly_rate or (staff.daily_rate / 8 if staff.daily_rate else 0)
            points_per_hour = float(get_points_config(db, 'points_per_hour', 10))  # Default: 10 points = 1 hour
            point_value = hourly_rate / points_per_hour if points_per_hour > 0 else 0

            for item in approved_items:
                if item.points > 0:
                    reward_points += item.points
                else:
                    penalty_points += abs(item.points)

            reward_adjustment = reward_points * point_value
            penalty_adjustment = penalty_points * point_value

            print(f"Points Calculation: Hourly Rate R{hourly_rate:.2f}, {points_per_hour} pts/hr, Point Value R{point_value:.2f}")
        except Exception as e:
            print(f"Error calculating rewards/penalties: {e}")

        total_deductions = loan_deduction + other_deductions + penalty_adjustment
        net_pay = gross_pay + reward_adjustment - total_deductions

        # DEBUG: Print deductions breakdown
        print(f"Loan Deductions: R {loan_deduction:.2f}")
        print(f"Other Deductions: R {other_deductions:.2f}")
        print(f"Reward Points: {reward_points} (R {reward_adjustment:.2f})")
        print(f"Penalty Points: {penalty_points} (R {penalty_adjustment:.2f})")
        print(f"Total Deductions: R {total_deductions:.2f}")
        print(f"NET PAY: R {net_pay:.2f}")
        print("="*70 + "\n")

        # Update payslip
        payslip.total_hours = total_hours
        payslip.weekday_hours = weekday_hours
        payslip.weekend_hours = weekend_hours
        payslip.weekday_pay = weekday_pay
        payslip.weekend_pay = weekend_pay
        payslip.overtime_pay = overtime_pay
        payslip.gross_pay = gross_pay
        payslip.loan_deduction = loan_deduction
        payslip.other_deductions = other_deductions
        payslip.reward_points = reward_points
        payslip.penalty_points = penalty_points
        payslip.reward_adjustment = reward_adjustment
        payslip.penalty_adjustment = penalty_adjustment
        payslip.total_deductions = total_deductions
        payslip.net_pay = net_pay

        # Reset verification when edited
        payslip.is_verified = False

        db.commit()

        return jsonify({
            'message': 'Payslip updated successfully',
            'net_pay': net_pay
        })

    finally:
        db.close()


@app.route('/api/payslips/<int:payslip_id>/autofill', methods=['POST'])
@token_required
@manager_or_admin_required
def autofill_payslip_from_attendance(current_user, payslip_id):
    """
    Auto-populate payslip days from attendance records.
    Maps clock-in/out times to day values (0, 0.5, or 1.0).
    """
    db = SessionLocal()
    try:
        payslip = db.query(Payslip).filter(Payslip.id == payslip_id).first()
        if not payslip:
            return jsonify({'error': 'Payslip not found'}), 404

        pay_period = payslip.pay_period
        staff_id = payslip.staff_id
        staff = payslip.staff

        # Get the date range from pay period
        start_date = pay_period.start_date
        end_date = pay_period.end_date

        import sys
        print(f"\n{'='*70}", file=sys.stderr)
        print(f"AUTOFILL PAYSLIP FROM ATTENDANCE", file=sys.stderr)
        print(f"Payslip ID: {payslip_id}", file=sys.stderr)
        print(f"Staff: {staff.full_name} (ID: {staff_id})", file=sys.stderr)
        print(f"Pay Period ID: {pay_period.id}", file=sys.stderr)
        print(f"Pay Period: {start_date} to {end_date}", file=sys.stderr)
        print(f"{'='*70}", file=sys.stderr)
        sys.stderr.flush()

        # Get all attendance records for this staff in the date range
        # Convert dates to strings for SQLite comparison (dates stored as strings)
        # Handle both date objects and strings
        if hasattr(start_date, 'strftime'):
            start_str = start_date.strftime('%Y-%m-%d')
            end_str = end_date.strftime('%Y-%m-%d')
        else:
            start_str = str(start_date)
            end_str = str(end_date)

        attendance_records = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == staff_id,
            WorkerAttendance.work_date >= start_str,
            WorkerAttendance.work_date <= end_str,
            WorkerAttendance.signin_time.isnot(None)  # Must have signed in
        ).all()

        print(f"  Found {len(attendance_records)} attendance records", file=sys.stderr)
        print(f"  Query: staff_id={staff_id}, work_date >= '{start_str}' AND <= '{end_str}'", file=sys.stderr)
        sys.stderr.flush()

        # Also check for leave records
        leave_records = db.query(LeaveRecord).filter(
            LeaveRecord.staff_id == staff_id,
            LeaveRecord.leave_date >= start_str,
            LeaveRecord.leave_date <= end_str,
            LeaveRecord.status != LeaveStatus.CANCELLED
        ).all()

        # Create a dict of attendance by date (using string keys for consistency)
        attendance_by_date = {}
        for att in attendance_records:
            # Convert to string for consistent lookup
            date_val = att.work_date
            if hasattr(date_val, 'strftime'):
                date_key = date_val.strftime('%Y-%m-%d')
            else:
                date_key = str(date_val)
            if date_key not in attendance_by_date:
                attendance_by_date[date_key] = []
            attendance_by_date[date_key].append(att)

        # Create a set of leave dates (as strings for consistency)
        leave_dates = set()
        for leave in leave_records:
            ld = leave.leave_date
            if hasattr(ld, 'strftime'):
                leave_dates.add(ld.strftime('%Y-%m-%d'))
            else:
                leave_dates.add(str(ld))

        # Map day index to payslip field name
        # Pay period starts on a specific day - need to map correctly
        # Week 1: days 0-6 from start_date
        # Week 2: days 7-13 from start_date

        # Convert start_date to date object if it's a string
        from datetime import datetime as dt
        if isinstance(start_date, str):
            start_date_obj = dt.strptime(start_date, '%Y-%m-%d').date()
        else:
            start_date_obj = start_date

        day_fields = {}
        for day_offset in range(14):
            current_date = start_date_obj + timedelta(days=day_offset)
            weekday = current_date.weekday()  # 0=Monday, 6=Sunday

            # Determine week number (1 or 2)
            week = 1 if day_offset < 7 else 2
            week_prefix = f'w{week}_'

            # Map weekday to field name
            weekday_names = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
            field_name = week_prefix + weekday_names[weekday]

            # Use string date as key for consistency with database
            day_fields[current_date.strftime('%Y-%m-%d')] = field_name

        # Calculate day values based on attendance
        # Work day = 8 hours, but gross clock hours include breaks
        # Breaks: 1 hour lunch + 0.5 hour tea = 1.5 hours
        # So gross 9.5 hours = 8 hours work time = full day
        # Full day work hours threshold = 8 hours (after break deduction)
        # Half day work hours threshold = 4 hours (after break deduction)
        day_values = {}
        BREAK_HOURS = 1.5  # 1hr lunch + 30min tea
        FULL_DAY_WORK_HOURS = 8.0  # Net work hours for full day
        HALF_DAY_WORK_HOURS = 4.0  # Net work hours for half day

        for current_date, field_name in day_fields.items():
            # Check if on leave - mark as 0 (not worked/unpaid)
            if current_date in leave_dates:
                day_values[field_name] = 0.0
                print(f"  {current_date} ({field_name}): ON LEAVE -> 0.0")
                continue

            # Check attendance records for this date
            if current_date in attendance_by_date:
                records = attendance_by_date[current_date]
                gross_hours = 0.0

                for att in records:
                    if att.signin_time and att.signout_time:
                        # Calculate gross hours from actual clock times
                        delta = att.signout_time - att.signin_time
                        hours = delta.total_seconds() / 3600
                        gross_hours += hours
                    elif att.signin_time:
                        # Signed in but not out yet - assume half day gross for now
                        gross_hours += HALF_DAY_WORK_HOURS + BREAK_HOURS

                # Subtract break time to get net work hours
                # Only deduct full break if worked long enough for a full day
                if gross_hours >= FULL_DAY_WORK_HOURS + BREAK_HOURS - 0.5:
                    work_hours = gross_hours - BREAK_HOURS
                elif gross_hours >= HALF_DAY_WORK_HOURS + 0.5:
                    # Half day - deduct smaller break (just 30 min tea)
                    work_hours = gross_hours - 0.5
                else:
                    work_hours = gross_hours

                # Determine day value based on net work hours
                if work_hours >= FULL_DAY_WORK_HOURS - 0.5:  # Allow 30 min tolerance for full day
                    day_value = 1.0
                elif work_hours >= HALF_DAY_WORK_HOURS - 0.5:  # Allow 30 min tolerance for half day
                    day_value = 0.5
                elif work_hours > 0:
                    day_value = 0.5  # Any attendance counts as at least half day
                else:
                    day_value = 0.0

                day_values[field_name] = day_value
                print(f"  {current_date} ({field_name}): gross={gross_hours:.1f}h, net={work_hours:.1f}h -> {day_value}")
            else:
                # No attendance record - not worked
                day_values[field_name] = 0.0
                print(f"  {current_date} ({field_name}): NO ATTENDANCE -> 0.0")

        # Update the payslip with the calculated values
        payslip.w1_monday = day_values.get('w1_monday', 0.0)
        payslip.w1_tuesday = day_values.get('w1_tuesday', 0.0)
        payslip.w1_wednesday = day_values.get('w1_wednesday', 0.0)
        payslip.w1_thursday = day_values.get('w1_thursday', 0.0)
        payslip.w1_friday = day_values.get('w1_friday', 0.0)
        payslip.w1_saturday = day_values.get('w1_saturday', 0.0)
        payslip.w1_sunday = day_values.get('w1_sunday', 0.0)
        payslip.w2_monday = day_values.get('w2_monday', 0.0)
        payslip.w2_tuesday = day_values.get('w2_tuesday', 0.0)
        payslip.w2_wednesday = day_values.get('w2_wednesday', 0.0)
        payslip.w2_thursday = day_values.get('w2_thursday', 0.0)
        payslip.w2_friday = day_values.get('w2_friday', 0.0)
        payslip.w2_saturday = day_values.get('w2_saturday', 0.0)
        payslip.w2_sunday = day_values.get('w2_sunday', 0.0)

        # Recalculate pay (same logic as update_payslip)
        staff = payslip.staff
        payslip.daily_rate = staff.daily_rate or 0.0
        payslip.hourly_rate = staff.hourly_rate or 0.0
        daily_rate = payslip.daily_rate
        hourly_rate = payslip.hourly_rate

        w1_weekdays = sum([payslip.w1_monday, payslip.w1_tuesday, payslip.w1_wednesday,
                          payslip.w1_thursday, payslip.w1_friday])
        w1_weekends = sum([payslip.w1_saturday, payslip.w1_sunday])
        w1_weekend_multiplier = 1.5 if w1_weekdays >= 3 else 1.0

        w2_weekdays = sum([payslip.w2_monday, payslip.w2_tuesday, payslip.w2_wednesday,
                          payslip.w2_thursday, payslip.w2_friday])
        w2_weekends = sum([payslip.w2_saturday, payslip.w2_sunday])
        w2_weekend_multiplier = 1.5 if w2_weekdays >= 3 else 1.0

        weekdays_worked = w1_weekdays + w2_weekdays
        weekends_worked = w1_weekends + w2_weekends

        STANDARD_HOURS_PER_DAY = 8.0
        weekday_hours = weekdays_worked * STANDARD_HOURS_PER_DAY
        weekend_hours = weekends_worked * STANDARD_HOURS_PER_DAY
        total_hours = weekday_hours + weekend_hours

        if daily_rate > 0:
            weekday_pay = weekdays_worked * daily_rate
            w1_weekend_pay = w1_weekends * daily_rate * w1_weekend_multiplier
            w2_weekend_pay = w2_weekends * daily_rate * w2_weekend_multiplier
            weekend_pay = w1_weekend_pay + w2_weekend_pay
        else:
            weekday_pay = weekday_hours * hourly_rate
            weekend_pay = weekend_hours * hourly_rate * 1.5

        overtime_pay = (payslip.overtime_hours or 0.0) * hourly_rate * 1.5
        gross_pay = weekday_pay + weekend_pay + overtime_pay + (payslip.bonus or 0.0)

        payslip.total_hours = total_hours
        payslip.weekday_hours = weekday_hours
        payslip.weekend_hours = weekend_hours
        payslip.weekday_pay = weekday_pay
        payslip.weekend_pay = weekend_pay
        payslip.overtime_pay = overtime_pay
        payslip.gross_pay = gross_pay

        # Calculate deductions
        active_loans = db.query(Loan).filter(
            Loan.staff_id == staff_id,
            Loan.is_active == True,
            Loan.is_completed == False
        ).all()
        loan_deduction = sum((loan.installment_amount or 0) for loan in active_loans)

        deductions = db.query(Deduction).filter(
            Deduction.staff_id == staff_id,
            Deduction.is_active == True
        ).all()
        other_deduction = sum(
            (d.amount or 0) if d.deduction_type == 'fixed' else (gross_pay * (d.percentage or 0) / 100)
            for d in deductions
        )

        total_deductions = loan_deduction + other_deduction
        net_pay = gross_pay - total_deductions

        payslip.loan_deduction = loan_deduction
        payslip.other_deductions = other_deduction
        payslip.total_deductions = total_deductions
        payslip.net_pay = net_pay
        payslip.is_verified = False

        db.commit()

        print(f"\n  SUMMARY:")
        print(f"  Weekdays: {weekdays_worked}, Weekends: {weekends_worked}")
        print(f"  Gross: R{gross_pay:.2f}, Net: R{net_pay:.2f}")
        print(f"{'='*70}\n")

        # Calculate summary for frontend display
        full_days = sum(1 for v in day_values.values() if v == 1.0)
        half_days = sum(1 for v in day_values.values() if v == 0.5)
        no_attendance = sum(1 for v in day_values.values() if v == 0.0)

        return jsonify({
            'success': True,
            'message': f'Auto-filled {sum(1 for v in day_values.values() if v > 0)} days from attendance',
            'days': day_values,
            'attendance_records': len(attendance_records),
            'leave_days': len(leave_dates),
            'gross_pay': gross_pay,
            'net_pay': net_pay,
            'summary': {
                'total_full_days': full_days,
                'total_half_days': half_days,
                'leave_days': len(leave_dates),
                'no_attendance_days': no_attendance
            }
        })

    except Exception as e:
        db.rollback()
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# ===== LOANS =====

@app.route('/api/loans/staff/<int:staff_id>', methods=['GET'])
@token_required
def get_staff_loans(current_user, staff_id):
    """Get loan summary and transactions for a staff member"""
    db = SessionLocal()
    try:
        staff = db.query(StaffMember).filter(StaffMember.id == staff_id).first()
        if not staff:
            return jsonify({'error': 'Staff member not found'}), 404

        # Get all loans for this staff
        loans = db.query(Loan).filter(Loan.staff_id == staff_id).order_by(Loan.loan_date.desc()).all()

        # Calculate summary
        active_loans = [l for l in loans if l.is_active and not l.is_completed]
        current_balance = sum(l.amount_remaining for l in active_loans)
        total_borrowed = sum(l.total_amount for l in loans)
        total_repaid = sum(l.amount_paid for l in loans)
        next_deduction = sum(l.installment_amount for l in active_loans)

        summary = {
            'current_balance': current_balance,
            'total_borrowed': total_borrowed,
            'total_repaid': total_repaid,
            'max_loan_amount': staff.max_loan_amount or 0,
            'active_loans_count': len(active_loans),
            'next_deduction': next_deduction
        }

        # Active loans details
        active_loans_data = []
        for loan in active_loans:
            payments_made = int(loan.amount_paid / loan.installment_amount) if loan.installment_amount > 0 else 0
            progress = (loan.amount_paid / loan.total_amount * 100) if loan.total_amount > 0 else 0

            active_loans_data.append({
                'id': loan.id,
                'description': loan.description,
                'loan_date': loan.loan_date.isoformat() if loan.loan_date else None,
                'total_amount': loan.total_amount,
                'amount_paid': loan.amount_paid,
                'amount_remaining': loan.amount_remaining,
                'installment_amount': loan.installment_amount,
                'total_installments': loan.total_installments,
                'payments_made': payments_made,
                'progress_percentage': progress
            })

        # Get recent loan transactions (last 20)
        transactions = db.query(LoanTransaction).join(Loan).filter(
            Loan.staff_id == staff_id
        ).order_by(LoanTransaction.transaction_date.desc()).limit(20).all()

        transactions_data = []
        for txn in transactions:
            transactions_data.append({
                'id': txn.id,
                'transaction_date': txn.transaction_date.isoformat(),
                'transaction_type': txn.transaction_type,
                'description': txn.description,
                'amount': txn.amount,
                'balance_after': txn.balance_after,
                'loan_id': txn.loan_id
            })

        return jsonify({
            'summary': summary,
            'active_loans': active_loans_data,
            'recent_transactions': transactions_data
        })
    finally:
        db.close()


@app.route('/api/loans', methods=['POST'])
@token_required
@manager_or_admin_required
def create_loan(current_user):
    """Create new loan"""
    db = SessionLocal()
    try:
        data = request.json

        loan = Loan(
            staff_id=data['staff_id'],
            description=data['description'],
            total_amount=float(data['total_amount']),
            amount_paid=0.0,
            amount_remaining=float(data['total_amount']),
            installment_amount=float(data['installment_amount']),
            loan_date=datetime.fromisoformat(data['loan_date']).date() if data.get('loan_date') else date.today(),
            start_deduction_date=datetime.fromisoformat(data['start_deduction_date']).date() if data.get('start_deduction_date') else date.today(),
            notes=data.get('notes'),
            created_by_id=current_user.id
        )

        db.add(loan)
        db.commit()
        db.refresh(loan)

        # Create disbursement transaction
        transaction = LoanTransaction(
            loan_id=loan.id,
            staff_id=loan.staff_id,
            transaction_type='disbursement',
            amount=loan.total_amount,
            balance_before=0.0,
            balance_after=loan.total_amount,
            description='Loan disbursement',
            transaction_date=loan.loan_date,
            created_by_id=current_user.id
        )
        db.add(transaction)
        db.commit()

        return jsonify({
            'id': loan.id,
            'message': 'Loan created successfully'
        }), 201

    finally:
        db.close()


@app.route('/api/loans/<int:loan_id>/repayment', methods=['POST'])
@token_required
@manager_or_admin_required
def record_loan_repayment(current_user, loan_id):
    """Record a manual loan repayment"""
    data = request.get_json()
    db = SessionLocal()

    try:
        loan = db.query(Loan).filter(Loan.id == loan_id).first()
        if not loan:
            return jsonify({'error': 'Loan not found'}), 404

        amount = float(data.get('amount', 0))
        if amount <= 0:
            return jsonify({'error': 'Repayment amount must be greater than 0'}), 400

        if amount > loan.amount_remaining:
            return jsonify({'error': f'Repayment amount cannot exceed remaining balance of R{loan.amount_remaining:.2f}'}), 400

        # Store old balance
        balance_before = loan.amount_remaining

        # Update loan
        loan.amount_paid += amount
        loan.amount_remaining -= amount

        # Check if loan is completed
        if loan.amount_remaining <= 0.01:  # Allow for floating point rounding
            loan.amount_remaining = 0
            loan.is_completed = True
            loan.is_active = False

        # Create repayment transaction
        transaction = LoanTransaction(
            loan_id=loan.id,
            staff_id=loan.staff_id,
            transaction_type='repayment',
            amount=amount,
            balance_before=balance_before,
            balance_after=loan.amount_remaining,
            description=data.get('notes', 'Manual repayment'),
            transaction_date=datetime.utcnow(),
            created_by_id=current_user.id
        )

        db.add(transaction)
        db.commit()

        return jsonify({
            'message': 'Repayment recorded successfully',
            'amount_remaining': loan.amount_remaining,
            'is_completed': loan.is_completed
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 400
    finally:
        db.close()


@app.route('/api/loans/transactions/<int:transaction_id>', methods=['DELETE'])
@token_required
@manager_or_admin_required
def delete_loan_transaction(current_user, transaction_id):
    """Delete a loan transaction and recalculate loan balance"""
    db = SessionLocal()
    try:
        from app.models import LoanTransaction

        transaction = db.query(LoanTransaction).filter(LoanTransaction.id == transaction_id).first()
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404

        loan = transaction.loan
        amount = transaction.amount
        txn_type = transaction.transaction_type

        # Delete the transaction
        db.delete(transaction)

        # Recalculate loan balance
        if txn_type == 'repayment':
            # If deleting a repayment, add the amount back to remaining
            loan.amount_paid -= amount
            loan.amount_remaining += amount
            loan.is_completed = False
        elif txn_type == 'disbursement':
            # If deleting disbursement, reduce remaining (rare case)
            loan.amount_remaining -= amount

        db.commit()

        return jsonify({
            'message': 'Transaction deleted successfully',
            'amount_remaining': loan.amount_remaining,
            'amount_paid': loan.amount_paid
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 400
    finally:
        db.close()


# ===== DEDUCTIONS =====

@app.route('/api/deductions', methods=['GET'])
@token_required
def get_deductions(current_user):
    """Get deductions for a staff member"""
    db = SessionLocal()
    try:
        staff_id = request.args.get('staff_id')
        if not staff_id:
            return jsonify({'error': 'staff_id required'}), 400

        deductions = db.query(Deduction).filter(Deduction.staff_id == int(staff_id)).all()

        return jsonify([{
            'id': d.id,
            'description': d.description,
            'deduction_type': d.deduction_type,
            'percentage': d.percentage,
            'fixed_amount': d.fixed_amount,
            'is_active': d.is_active,
            'start_date': d.start_date.isoformat() if d.start_date else None,
            'end_date': d.end_date.isoformat() if d.end_date else None,
            'notes': d.notes
        } for d in deductions])
    finally:
        db.close()


@app.route('/api/deductions', methods=['POST'])
@token_required
@manager_or_admin_required
def create_deduction(current_user):
    """Create new deduction"""
    db = SessionLocal()
    try:
        data = request.json

        deduction = Deduction(
            staff_id=data['staff_id'],
            description=data['description'],
            deduction_type=data['deduction_type'],
            percentage=float(data['percentage']) if data.get('percentage') else None,
            fixed_amount=float(data['fixed_amount']) if data.get('fixed_amount') else None,
            start_date=datetime.fromisoformat(data['start_date']).date() if data.get('start_date') else None,
            end_date=datetime.fromisoformat(data['end_date']).date() if data.get('end_date') else None,
            notes=data.get('notes'),
            created_by_id=current_user.id
        )

        db.add(deduction)
        db.commit()
        db.refresh(deduction)

        return jsonify({
            'id': deduction.id,
            'message': 'Deduction created successfully'
        }), 201

    finally:
        db.close()


@app.route('/api/deductions/<int:deduction_id>/toggle', methods=['POST'])
@token_required
@manager_or_admin_required
def toggle_deduction(current_user, deduction_id):
    """Toggle deduction active status"""
    db = SessionLocal()
    try:
        deduction = db.query(Deduction).filter(Deduction.id == deduction_id).first()
        if not deduction:
            return jsonify({'error': 'Deduction not found'}), 404

        deduction.is_active = not deduction.is_active
        db.commit()

        return jsonify({
            'message': f'Deduction {"activated" if deduction.is_active else "deactivated"} successfully',
            'is_active': deduction.is_active
        })

    finally:
        db.close()


# ===== SAVINGS =====

@app.route('/api/savings/staff/<int:staff_id>', methods=['GET'])
@token_required
def get_staff_savings(current_user, staff_id):
    """Get savings account and transactions for a staff member"""
    db = SessionLocal()
    try:
        # Get or create savings account
        account = db.query(SavingsAccount).filter(SavingsAccount.staff_id == staff_id).first()

        if not account:
            return jsonify({
                'account': None,
                'transactions': []
            })

        # Get transactions
        transactions = db.query(SavingsTransaction).filter(
            SavingsTransaction.staff_id == staff_id
        ).order_by(SavingsTransaction.transaction_date.desc()).all()

        return jsonify({
            'account': {
                'id': account.id,
                'total_balance': account.total_balance,
                'recurring_amount': account.recurring_amount,
                'is_active': account.is_active,
                'created_at': account.created_at.isoformat() if account.created_at else None
            },
            'transactions': [{
                'id': t.id,
                'transaction_type': t.transaction_type,
                'amount': t.amount,
                'balance_after': t.balance_after,
                'description': t.description,
                'transaction_date': t.transaction_date.isoformat() if t.transaction_date else None,
                'created_at': t.created_at.isoformat() if t.created_at else None
            } for t in transactions]
        })

    finally:
        db.close()


@app.route('/api/savings', methods=['POST'])
@token_required
@manager_or_admin_required
def create_savings_transaction(current_user):
    """Create a savings transaction (deposit or withdrawal)"""
    db = SessionLocal()
    try:
        data = request.json
        staff_id = data['staff_id']

        # Get or create savings account
        account = db.query(SavingsAccount).filter(SavingsAccount.staff_id == staff_id).first()
        if not account:
            account = SavingsAccount(
                staff_id=staff_id,
                total_balance=0.0,
                recurring_amount=0.0,
                is_active=True
            )
            db.add(account)
            db.flush()

        transaction_type = data['transaction_type']  # 'deposit' or 'withdrawal'
        amount = float(data['amount'])

        # Calculate new balance
        if transaction_type == 'deposit':
            new_balance = account.total_balance + amount
        elif transaction_type == 'withdrawal':
            if amount > account.total_balance:
                return jsonify({'error': 'Insufficient savings balance'}), 400
            new_balance = account.total_balance - amount
        else:
            return jsonify({'error': 'Invalid transaction type'}), 400

        # Create transaction
        transaction = SavingsTransaction(
            savings_account_id=account.id,
            staff_id=staff_id,
            transaction_type=transaction_type,
            amount=amount,
            balance_after=new_balance,
            description=data.get('description', f'{transaction_type.capitalize()} - {date.today()}'),
            notes=data.get('notes'),
            transaction_date=date.today(),
            created_by_id=current_user.id
        )
        db.add(transaction)

        # Update account balance
        account.total_balance = new_balance
        account.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(transaction)

        return jsonify({
            'id': transaction.id,
            'message': f'{transaction_type.capitalize()} successful',
            'new_balance': new_balance
        }), 201

    finally:
        db.close()


@app.route('/api/savings/<int:account_id>/recurring', methods=['PUT'])
@token_required
@manager_or_admin_required
def update_recurring_savings(current_user, account_id):
    """Update recurring savings amount"""
    db = SessionLocal()
    try:
        account = db.query(SavingsAccount).filter(SavingsAccount.id == account_id).first()
        if not account:
            return jsonify({'error': 'Savings account not found'}), 404

        data = request.json
        account.recurring_amount = float(data['recurring_amount'])
        account.updated_at = datetime.utcnow()

        db.commit()

        return jsonify({
            'message': 'Recurring savings amount updated',
            'recurring_amount': account.recurring_amount
        })

    finally:
        db.close()


# ===== PAYSLIP APPROVAL & PDF GENERATION =====

@app.route('/api/payslips/<int:payslip_id>/approve', methods=['POST'])
@token_required
@manager_or_admin_required
def approve_payslip(current_user, payslip_id):
    """Toggle payslip approval status"""
    db = SessionLocal()
    try:
        payslip = db.query(Payslip).filter(Payslip.id == payslip_id).first()
        if not payslip:
            return jsonify({'error': 'Payslip not found'}), 404

        # Store old approval status to detect transition to approved
        was_approved = payslip.is_approved

        # Toggle approval status
        payslip.is_approved = not payslip.is_approved
        db.commit()

        # Send SMS notification if payslip was just approved (not unapproved)
        if payslip.is_approved and not was_approved:
            try:
                staff = payslip.staff
                if staff.mobile:
                    # Get pay period dates
                    pay_period = payslip.pay_period
                    start_date = pay_period.start_date.strftime("%d/%m/%y") if pay_period and pay_period.start_date else "N/A"
                    end_date = pay_period.end_date.strftime("%d/%m/%y") if pay_period and pay_period.end_date else "N/A"

                    # Determine payment method from staff bank details
                    # payment_method_type = payslip.payment_method or 'BANK'  # COMMENTED OUT - column doesn't exist in DB
                    if staff.bank_name and staff.bank_account:
                        payment_method = f"{staff.bank_name} {staff.bank_account}"
                    else:
                        payment_method = "CASH"

                    # Get loan status
                    active_loans = db.query(Loan).filter(
                        Loan.staff_id == staff.id,
                        Loan.is_active == True
                    ).all()
                    total_loan_balance = sum(loan.amount_remaining for loan in active_loans)

                    # Get savings balance
                    savings_account = db.query(SavingsAccount).filter(
                        SavingsAccount.staff_id == staff.id
                    ).first()
                    savings_balance = savings_account.total_balance if savings_account else 0.0

                    # Send SMS notification
                    notifier = SMSNotifier()
                    success = notifier.send_payslip_verification_sms(
                        staff_name=staff.full_name,
                        mobile=staff.mobile,
                        start_date=start_date,
                        end_date=end_date,
                        gross_pay=payslip.gross_pay or 0.0,
                        deductions=payslip.total_deductions or 0.0,
                        net_pay=payslip.net_pay or 0.0,
                        payment_method=payment_method,
                        loan_balance=total_loan_balance,
                        loan_deduction=payslip.loan_deduction or 0.0,
                        savings_balance=savings_balance
                    )

                    if success:
                        print(f"[SMS] Notification sent to {staff.full_name} ({staff.mobile})")
                    else:
                        print(f"[SMS] Failed to send notification to {staff.full_name}")
                else:
                    print(f"[SMS] No mobile number for {staff.full_name}, skipping notification")
            except Exception as e:
                # Don't fail the approval if SMS fails
                print(f"[ERROR] SMS notification failed: {e}")

        return jsonify({
            'message': f'Payslip {"approved" if payslip.is_approved else "unapproved"}',
            'is_approved': payslip.is_approved
        })

    finally:
        db.close()


@app.route('/api/payslips/generate-pdfs/<int:pay_period_id>', methods=['POST'])
@token_required
@manager_or_admin_required
def generate_payslip_pdfs(current_user, pay_period_id):
    """
    Generate PDF payslips for all approved payslips in a pay period
    Only generates PDFs for payslips where is_approved = True
    """
    from app.payslip_pdf import generate_payslip_pdf
    import os

    db = SessionLocal()

    try:
        # Get pay period
        pay_period = db.query(PayPeriod).filter(PayPeriod.id == pay_period_id).first()
        if not pay_period:
            return jsonify({'error': 'Pay period not found'}), 404

        # Get all payslips for this period
        payslips = db.query(Payslip).filter(Payslip.pay_period_id == pay_period_id).all()

        generated_count = 0
        not_approved_count = 0
        error_count = 0
        pdf_files = []

        # Create payslips directory
        period_folder = f"{pay_period.year}-Period-{pay_period.period_number}"
        output_dir = os.path.join('c:\\wagepro\\payslips', period_folder)
        os.makedirs(output_dir, exist_ok=True)

        for payslip in payslips:
            # Skip if not approved
            if not payslip.is_approved:
                not_approved_count += 1
                continue

            try:
                # Get staff details
                staff = db.query(StaffMember).filter(StaffMember.id == payslip.staff_id).first()
                if not staff:
                    error_count += 1
                    continue

                # Get loans for this payslip
                active_loans = db.query(Loan).filter(
                    Loan.staff_id == staff.id,
                    Loan.is_active == True,
                    Loan.is_completed == False
                ).all()

                loans_data = [{
                    'description': loan.description,
                    'installment_amount': loan.installment_amount,
                    'amount_remaining': loan.amount_remaining
                } for loan in active_loans]

                # Calculate loan summary
                total_loan_balance = sum(loan.amount_remaining for loan in active_loans)
                total_loan_repayment = sum(loan.installment_amount for loan in active_loans)

                # Get savings account
                savings_account = db.query(SavingsAccount).filter(
                    SavingsAccount.staff_id == staff.id
                ).first()

                savings_balance = savings_account.total_balance if savings_account else 0.0

                # Get deductions
                active_deductions = db.query(Deduction).filter(
                    Deduction.staff_id == staff.id,
                    Deduction.is_active == True
                ).all()

                deductions_data = []
                for deduction in active_deductions:
                    if deduction.deduction_type in ['fixed', 'once_off']:
                        amount = deduction.fixed_amount or 0
                    elif deduction.deduction_type == 'percentage':
                        amount = (payslip.gross_pay * (deduction.percentage or 0) / 100)
                    else:
                        amount = 0

                    deductions_data.append({
                        'description': deduction.description,
                        'deduction_type': deduction.deduction_type,
                        'amount': amount
                    })

                # Prepare payslip data (without public holiday fields for now)
                payslip_data = {
                    'staff_id': staff.id,
                    'staff_name': staff.full_name,
                    'position': staff.position,
                    'pay_period_start': pay_period.start_date.strftime('%d/%m/%Y'),
                    'pay_period_end': pay_period.end_date.strftime('%d/%m/%Y'),
                    'paid_at': payslip.paid_at.strftime('%d/%m/%Y') if payslip.paid_at else pay_period.end_date.strftime('%d/%m/%Y'),

                    # Days worked
                    'w1_monday': payslip.w1_monday,
                    'w1_tuesday': payslip.w1_tuesday,
                    'w1_wednesday': payslip.w1_wednesday,
                    'w1_thursday': payslip.w1_thursday,
                    'w1_friday': payslip.w1_friday,
                    'w1_saturday': payslip.w1_saturday,
                    'w1_sunday': payslip.w1_sunday,
                    'w2_monday': payslip.w2_monday,
                    'w2_tuesday': payslip.w2_tuesday,
                    'w2_wednesday': payslip.w2_wednesday,
                    'w2_thursday': payslip.w2_thursday,
                    'w2_friday': payslip.w2_friday,
                    'w2_saturday': payslip.w2_saturday,
                    'w2_sunday': payslip.w2_sunday,

                    # Earnings
                    'weekday_pay': payslip.weekday_pay,
                    'weekend_pay': payslip.weekend_pay,
                    'public_holiday_hours': 0,  # Not yet implemented
                    'public_holiday_pay': 0,    # Not yet implemented
                    'overtime_pay': payslip.overtime_pay,
                    'bonus': payslip.bonus,
                    'gross_pay': payslip.gross_pay,

                    # Deductions
                    'loans': loans_data,
                    'deductions': deductions_data,
                    'savings_deduction': 0,  # Will be implemented with savings deduction feature
                    'total_deductions': payslip.total_deductions,

                    # Net pay
                    'net_pay': payslip.net_pay,

                    # Loan Summary
                    'total_loan_balance': total_loan_balance,
                    'total_loan_repayment': total_loan_repayment,

                    # Savings Summary
                    'savings_balance': savings_balance
                }

                # Generate filename - sanitize for Windows filesystem
                # Remove invalid chars: * ? " < > | : \ /
                staff_name_safe = staff.full_name
                staff_name_safe = re.sub(r'[*?"<>|:\\\/]', '', staff_name_safe)  # Remove invalid chars
                staff_name_safe = staff_name_safe.replace(' ', '_').strip('_')
                filename = f"{staff_name_safe}_{pay_period.year}-{pay_period.period_number}.pdf"
                output_path = os.path.join(output_dir, filename)

                # Generate PDF
                generate_payslip_pdf(payslip_data, output_path)

                pdf_files.append(filename)
                generated_count += 1

            except Exception as e:
                print(f"Error generating PDF for payslip {payslip.id}: {str(e)}")
                error_count += 1
                continue

        # Build response message
        messages = []
        if generated_count > 0:
            messages.append(f"Generated {generated_count} payslip PDF(s)")
        if not_approved_count > 0:
            messages.append(f"{not_approved_count} not approved")
        if error_count > 0:
            messages.append(f"{error_count} error(s)")

        return jsonify({
            'generated': generated_count,
            'not_approved': not_approved_count,
            'errors': error_count,
            'pdf_files': pdf_files,
            'message': ', '.join(messages) if messages else 'No PDFs generated',
            'output_dir': output_dir
        })

    finally:
        db.close()


@app.route('/api/payslips/send-sms/<int:pay_period_id>', methods=['POST'])
@token_required
@manager_or_admin_required
def send_payslip_sms(current_user, pay_period_id):
    """
    Send SMS notifications to staff with mobile numbers for approved payslips
    Only sends to staff who have mobile numbers recorded
    """
    db = SessionLocal()

    try:
        # Get pay period
        pay_period = db.query(PayPeriod).filter(PayPeriod.id == pay_period_id).first()
        if not pay_period:
            return jsonify({'error': 'Pay period not found'}), 404

        # Get all approved payslips for this period
        payslips = db.query(Payslip).filter(
            Payslip.pay_period_id == pay_period_id,
            Payslip.is_approved == True
        ).all()

        if not payslips:
            return jsonify({'error': 'No approved payslips found'}), 400

        # Build messages list
        messages = []
        sent_count = 0
        no_mobile_count = 0
        period_info = f"{pay_period.start_date.strftime('%d/%m')}-{pay_period.end_date.strftime('%d/%m/%Y')}"

        for payslip in payslips:
            staff = db.query(StaffMember).filter(StaffMember.id == payslip.staff_id).first()
            if not staff:
                continue

            # Use phone field (mobile is often empty, phone has the number)
            mobile = staff.mobile or staff.phone
            if not mobile or not mobile.strip():
                no_mobile_count += 1
                continue

            # Build SMS message - WAGES - SITE - NAME - details
            site_name = (staff.site.name if staff.site else "WAGES").replace("_", " ")
            staff_name = staff.full_name
            message = f"WAGES {site_name} {staff_name} {period_info}: GROSS R{payslip.gross_pay:.2f}, DEDUCT R{payslip.total_deductions:.2f}, NET R{payslip.net_pay:.2f}"

            messages.append({
                'mobile': mobile,
                'message': message
            })
            sent_count += 1

        if not messages:
            return jsonify({
                'error': 'No staff with mobile numbers found',
                'no_mobile_count': no_mobile_count
            }), 400

        # Use SMSNotifier to create batch and upload
        notifier = SMSNotifier()
        batch_file = notifier.create_batch_file(messages)

        if batch_file:
            # Upload to WinSMS FTP
            success, upload_message = notifier.upload_to_winsms(batch_file)

            return jsonify({
                'success': success,
                'sent_count': sent_count,
                'no_mobile_count': no_mobile_count,
                'batch_file': batch_file,
                'upload_message': upload_message,
                'message': f"SMS sent to {sent_count} staff ({no_mobile_count} without mobile numbers)"
            })
        else:
            return jsonify({'error': 'Failed to create SMS batch file'}), 500

    finally:
        db.close()


@app.route('/api/manager/notify-submission', methods=['POST'])
@token_required
def notify_manager_submission(current_user):
    """
    Send SMS to admin when manager submits days worked
    Format: WAGEPRO SITE Wk1: KING 5, MIKE 5 | CORR: BOB 4>5
    """
    ADMIN_MOBILE = '0826000859'

    db = SessionLocal()
    try:
        data = request.json
        period_id = data.get('period_id')
        week = data.get('week', 1)
        new_entries = data.get('new_entries', [])
        corrections = data.get('corrections', [])

        # Get manager's site name (remove underscores)
        site_name = (current_user.site.name if current_user.site else "?").replace("_", " ")

        # Build new entries string: "KING-5,MIKE-5" (no space after comma to avoid underline)
        new_str = ",".join([f"{e['name']}-{e['days']}" for e in new_entries])

        # Build corrections string: "BOB-4>5,JIM-3>4"
        corr_str = ",".join([f"{c['name']}-{c['old']}>{c['new']}" for c in corrections])

        # Build SMS message
        parts = [f"WAGEPRO {site_name} Wk{week}:"]
        if new_str:
            parts.append(new_str)
        if corr_str:
            parts.append(f"CORR: {corr_str}")

        message = " ".join(parts)

        # If nothing to report
        if not new_str and not corr_str:
            message = f"WAGEPRO {site_name} Wk{week}: No changes"

        # Send via WinSMS
        notifier = SMSNotifier()
        messages = [{'mobile': ADMIN_MOBILE, 'message': message}]
        batch_file = notifier.create_batch_file(messages)

        if batch_file:
            success, upload_msg = notifier.upload_to_winsms(batch_file)
            return jsonify({
                'success': success,
                'message': f"Admin notified: {message}",
                'upload_message': upload_msg
            })
        else:
            return jsonify({'error': 'Failed to create SMS'}), 500

    finally:
        db.close()


@app.route('/api/staff/<int:staff_id>/payslip-history', methods=['GET'])
@token_required
def get_staff_payslip_history(current_user, staff_id):
    """
    Get complete payslip history for a specific staff member
    Returns all historical payslips with full breakdown
    """
    db = SessionLocal()
    try:
        # Get staff member
        staff = db.query(StaffMember).filter(StaffMember.id == staff_id).first()
        if not staff:
            return jsonify({'error': 'Staff member not found'}), 404

        # Get all payslips for this staff member, ordered by period
        payslips = db.query(Payslip).join(PayPeriod).filter(
            Payslip.staff_id == staff_id
        ).order_by(PayPeriod.year.desc(), PayPeriod.period_number.desc()).all()

        result = []
        for p in payslips:
            # Get pay period details
            period = db.query(PayPeriod).filter(PayPeriod.id == p.pay_period_id).first()

            # Get loan transactions for this payslip
            loan_transactions = db.query(LoanTransaction).filter(
                LoanTransaction.payslip_id == p.id
            ).all()

            loans_data = [{
                'id': lt.loan_id,
                'description': lt.description or 'Loan deduction',
                'amount': lt.amount,
                'balance': lt.balance_after
            } for lt in loan_transactions]

            result.append({
                'payslip_id': p.id,
                'period': f"{period.year} Period {period.period_number}",
                'period_start': period.start_date.strftime('%Y-%m-%d') if period.start_date else None,
                'period_end': period.end_date.strftime('%Y-%m-%d') if period.end_date else None,
                'gross_pay': p.gross_pay,
                'weekday_pay': p.weekday_pay,
                'weekend_pay': p.weekend_pay,
                'overtime_pay': p.overtime_pay,
                'bonus': p.bonus,
                'loans': loans_data,
                'loan_deduction': p.loan_deduction,
                'other_deductions': p.other_deductions,
                'total_deductions': p.total_deductions,
                'net_pay': p.net_pay,
                'payment_method': p.payment_method,
                'is_approved': p.is_approved,
                'is_paid': p.is_paid
            })

        return jsonify({
            'staff_id': staff.id,
            'staff_name': staff.full_name,
            'staff_position': staff.position,
            'staff_site': staff.site.name if staff.site else None,
            'payslips': result
        })

    finally:
        db.close()


@app.route('/api/staff/<int:staff_id>/sms-history', methods=['GET'])
@token_required
def get_staff_sms_history(current_user, staff_id):
    """
    Get SMS history for a specific staff member
    Supports filtering by time period: 'week', 'month', 'all'
    """
    db = SessionLocal()
    try:
        from datetime import datetime, timedelta

        # Get staff member
        staff = db.query(StaffMember).filter(StaffMember.id == staff_id).first()
        if not staff:
            return jsonify({'error': 'Staff member not found'}), 404

        # Get filter parameter
        filter_period = request.args.get('period', 'all')  # week, month, all

        # Build query
        query = db.query(SMSLog).filter(SMSLog.staff_id == staff_id)

        # Apply time filter
        now = datetime.now()
        if filter_period == 'week':
            start_date = now - timedelta(days=7)
            query = query.filter(SMSLog.sent_at >= start_date)
        elif filter_period == 'month':
            start_date = now - timedelta(days=30)
            query = query.filter(SMSLog.sent_at >= start_date)

        # Order by most recent first
        sms_logs = query.order_by(SMSLog.sent_at.desc()).all()

        result = []
        for sms in sms_logs:
            result.append({
                'id': sms.id,
                'phone_number': sms.phone_number,
                'message': sms.message,
                'sms_type': sms.sms_type.value if sms.sms_type else 'other',
                'sent_at': sms.sent_at.strftime('%Y-%m-%d %H:%M') if sms.sent_at else None,
                'status': sms.status
            })

        return jsonify({
            'staff_id': staff.id,
            'staff_name': staff.full_name,
            'sms_count': len(result),
            'filter': filter_period,
            'sms_logs': result
        })

    finally:
        db.close()


# ===== MOBILE DAILY WORK ENTRY =====

@app.route('/api/mobile/staff', methods=['GET'])
@token_required
def get_mobile_staff(current_user):
    """Get staff for manager's site (for mobile daily entry)"""
    db = SessionLocal()
    try:
        # Manager must have a site assigned
        if current_user.role.value != 'admin' and not current_user.site_id:
            return jsonify({'error': 'No site assigned to this manager'}), 403

        # Get active staff for this site
        query = db.query(StaffMember).filter(StaffMember.is_active == True)

        if current_user.role.value != 'admin':
            query = query.filter(StaffMember.site_id == current_user.site_id)

        staff = query.order_by(StaffMember.first_name).all()

        # Sort with managers first, then by name
        def sort_key(s):
            is_manager = 1 if s.position and 'manager' in s.position.lower() else 0
            return (-is_manager, s.first_name.lower() if s.first_name else '')

        staff_sorted = sorted(staff, key=sort_key)

        return jsonify({
            'site_id': current_user.site_id,
            'site_name': current_user.site.name if current_user.site else 'All Sites',
            'manager_name': current_user.full_name,
            'staff': [{
                'id': s.id,
                'name': s.full_name,
                'position': s.position,
                'department': s.department,
                'daily_rate': s.daily_rate or 0
            } for s in staff_sorted]
        })
    finally:
        db.close()


@app.route('/api/mobile/current-period', methods=['GET'])
@token_required
def get_mobile_current_period(current_user):
    """Get current open pay period for mobile entry"""
    db = SessionLocal()
    try:
        period = db.query(PayPeriod).filter(
            PayPeriod.status == PayPeriodStatus.OPEN
        ).order_by(PayPeriod.start_date.desc()).first()

        # Get site name for this user
        site_name = current_user.site.name if current_user.site else None

        if not period:
            return jsonify({
                'period': None,
                'site_name': site_name,
                'message': 'No open pay period'
            })

        return jsonify({
            'period': {
                'id': period.id,
                'period_number': period.period_number,
                'year': period.year,
                'start_date': period.start_date.isoformat(),
                'end_date': period.end_date.isoformat(),
                'status': period.status.value
            },
            'site_name': site_name
        })
    finally:
        db.close()


@app.route('/api/mobile/create-period', methods=['POST'])
@token_required
def create_mobile_pay_period(current_user):
    """Create a new pay period using Thursday-Wednesday cycle (14 days)

    Pay period cycle changed Dec 2025:
    - Old cycle: Saturday to Friday (14 days)
    - New cycle: Thursday to Wednesday (14 days), starting Dec 25, 2025
    """
    from datetime import timedelta

    db = SessionLocal()
    try:
        today = datetime.now().date()

        # New cycle transition date: Dec 25, 2025
        NEW_CYCLE_START = date(2025, 12, 25)

        # Check if there's already an open period
        existing = db.query(PayPeriod).filter(
            PayPeriod.status == PayPeriodStatus.OPEN
        ).first()

        if existing:
            # Check if the existing period has ended
            if today > existing.end_date:
                # Close the expired period
                existing.status = PayPeriodStatus.CLOSED
                db.commit()
            else:
                return jsonify({'error': 'An open pay period already exists'}), 400

        # Determine which cycle to use based on date
        if today >= NEW_CYCLE_START:
            # NEW CYCLE: Thursday to Wednesday (14 days)
            # weekday(): Mon=0, Tue=1, Wed=2, Thu=3, Fri=4, Sat=5, Sun=6
            # Thursday = 3
            days_since_thursday = (today.weekday() - 3) % 7  # Days since last Thursday
            start_date = today - timedelta(days=days_since_thursday)

            # Ensure we're aligned with the Dec 25, 2025 start
            # Calculate which fortnight we're in since Dec 25, 2025
            days_since_new_cycle = (start_date - NEW_CYCLE_START).days
            if days_since_new_cycle < 0:
                # Before the new cycle - use Dec 25 as start
                start_date = NEW_CYCLE_START
            else:
                # Align to correct fortnight
                fortnights_elapsed = days_since_new_cycle // 14
                start_date = NEW_CYCLE_START + timedelta(days=fortnights_elapsed * 14)

            end_date = start_date + timedelta(days=13)  # 14 days total, ends on Wednesday
        else:
            # OLD CYCLE: Saturday to Friday (for periods before Dec 25, 2025)
            days_since_saturday = (today.weekday() - 5) % 7  # Days since last Saturday
            start_date = today - timedelta(days=days_since_saturday)
            end_date = start_date + timedelta(days=13)  # 2 weeks ends on Friday

        # Calculate period number for this year
        year = start_date.year
        existing_periods = db.query(PayPeriod).filter(
            PayPeriod.year == year
        ).count()
        period_number = existing_periods + 1

        # Create the period
        period = PayPeriod(
            period_number=period_number,
            year=year,
            start_date=start_date,
            end_date=end_date,
            status=PayPeriodStatus.OPEN
        )
        db.add(period)
        db.commit()

        return jsonify({
            'success': True,
            'period': {
                'id': period.id,
                'period_number': period.period_number,
                'year': period.year,
                'start_date': period.start_date.isoformat(),
                'end_date': period.end_date.isoformat(),
                'status': period.status.value
            }
        })
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


def get_day_column_for_date(period_start_date, target_date):
    """
    Convert a date to the corresponding payslip day column (w1_monday, w2_tuesday, etc.)
    Returns column name and week number (1 or 2)

    Handles both old cycle (Saturday start) and new cycle (Thursday start).
    The column name is based on the actual day of the week, not the position in period.
    """
    from datetime import timedelta

    days_diff = (target_date - period_start_date).days

    if days_diff < 0 or days_diff > 13:
        return None, None

    week = 1 if days_diff < 7 else 2

    # Get actual day of week for the target date
    # weekday(): Mon=0, Tue=1, Wed=2, Thu=3, Fri=4, Sat=5, Sun=6
    day_of_week = target_date.weekday()

    day_names = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
    column_name = f"w{week}_{day_names[day_of_week]}"

    return column_name, week


@app.route('/api/mobile/daily-entry', methods=['GET'])
@token_required
def get_mobile_daily_entry(current_user):
    """Get work entries for a specific date"""
    db = SessionLocal()
    try:
        date_str = request.args.get('date')
        if not date_str:
            date_str = datetime.now().strftime('%Y-%m-%d')

        target_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        # Get current period
        period = db.query(PayPeriod).filter(
            PayPeriod.start_date <= target_date,
            PayPeriod.end_date >= target_date
        ).first()

        if not period:
            return jsonify({'error': 'No pay period found for this date'}), 404

        # Get the day column
        day_column, week = get_day_column_for_date(period.start_date, target_date)
        if not day_column:
            return jsonify({'error': 'Date not in valid range'}), 400

        # Get staff for this site
        staff_query = db.query(StaffMember).filter(StaffMember.is_active == True)
        if current_user.role.value != 'admin':
            if not current_user.site_id:
                return jsonify({'error': 'No site assigned'}), 403
            staff_query = staff_query.filter(StaffMember.site_id == current_user.site_id)

        staff_list = staff_query.order_by(StaffMember.first_name).all()

        # Get existing payslips for this period
        payslips = db.query(Payslip).filter(
            Payslip.pay_period_id == period.id,
            Payslip.staff_id.in_([s.id for s in staff_list])
        ).all()

        payslip_map = {p.staff_id: p for p in payslips}

        # Build response
        entries = []
        for staff in staff_list:
            payslip = payslip_map.get(staff.id)
            day_value = 0.0
            if payslip:
                day_value = getattr(payslip, day_column, 0.0) or 0.0

            entries.append({
                'staff_id': staff.id,
                'name': staff.full_name,
                'position': staff.position,
                'daily_rate': staff.daily_rate or 0,
                'day_value': day_value,  # 0=No work, 0.5=Half, 1=Full
                'has_payslip': payslip is not None,
                'payslip_id': payslip.id if payslip else None
            })

        return jsonify({
            'date': date_str,
            'day_name': target_date.strftime('%A'),
            'day_column': day_column,
            'week': week,
            'period_id': period.id,
            'period_start': period.start_date.isoformat(),
            'period_end': period.end_date.isoformat(),
            'site_name': current_user.site.name if current_user.site else 'All Sites',
            'entries': entries
        })
    finally:
        db.close()


@app.route('/api/mobile/daily-entry', methods=['POST'])
@token_required
def save_mobile_daily_entry(current_user):
    """Save work entry for a single staff member for a specific date"""
    db = SessionLocal()
    try:
        data = request.json
        staff_id = data.get('staff_id')
        date_str = data.get('date')
        day_value = float(data.get('day_value', 0))  # 0, 0.5, or 1

        if not staff_id or not date_str:
            return jsonify({'error': 'staff_id and date required'}), 400

        if day_value not in [0, 0.5, 1]:
            return jsonify({'error': 'day_value must be 0, 0.5, or 1'}), 400

        target_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        # Get staff and verify access
        staff = db.query(StaffMember).filter(StaffMember.id == staff_id).first()
        if not staff:
            return jsonify({'error': 'Staff not found'}), 404

        if current_user.role.value != 'admin' and staff.site_id != current_user.site_id:
            return jsonify({'error': 'Access denied - wrong site'}), 403

        # Get pay period
        period = db.query(PayPeriod).filter(
            PayPeriod.start_date <= target_date,
            PayPeriod.end_date >= target_date
        ).first()

        if not period:
            return jsonify({'error': 'No pay period for this date'}), 404

        if period.status.value not in ['open', 'processing']:
            return jsonify({'error': 'Pay period is closed'}), 400

        # Get day column
        day_column, week = get_day_column_for_date(period.start_date, target_date)
        if not day_column:
            return jsonify({'error': 'Invalid date for period'}), 400

        # Get or create payslip
        payslip = db.query(Payslip).filter(
            Payslip.pay_period_id == period.id,
            Payslip.staff_id == staff_id
        ).first()

        if not payslip:
            # Create new payslip
            payslip = Payslip(
                pay_period_id=period.id,
                staff_id=staff_id,
                hourly_rate=staff.hourly_rate or 0,
                daily_rate=staff.daily_rate or 0,
                net_pay=0,
                created_by_id=current_user.id
            )
            db.add(payslip)
            db.flush()

        # Update the specific day
        setattr(payslip, day_column, day_value)

        # Recalculate totals
        day_columns = [
            'w1_monday', 'w1_tuesday', 'w1_wednesday', 'w1_thursday', 'w1_friday', 'w1_saturday', 'w1_sunday',
            'w2_monday', 'w2_tuesday', 'w2_wednesday', 'w2_thursday', 'w2_friday', 'w2_saturday', 'w2_sunday'
        ]
        weekday_columns = [c for c in day_columns if not c.endswith('saturday') and not c.endswith('sunday')]
        weekend_columns = [c for c in day_columns if c.endswith('saturday') or c.endswith('sunday')]

        weekday_days = sum([getattr(payslip, c, 0) or 0 for c in weekday_columns])
        weekend_days = sum([getattr(payslip, c, 0) or 0 for c in weekend_columns])

        daily_rate = payslip.daily_rate or 0
        payslip.weekday_hours = weekday_days * 8  # Assuming 8 hour days
        payslip.weekend_hours = weekend_days * 8
        payslip.total_hours = (weekday_days + weekend_days) * 8
        payslip.weekday_pay = weekday_days * daily_rate
        payslip.weekend_pay = weekend_days * daily_rate * 1.5  # Weekend premium
        payslip.gross_pay = payslip.weekday_pay + payslip.weekend_pay + (payslip.overtime_pay or 0) + (payslip.bonus or 0)
        payslip.total_deductions = (payslip.loan_deduction or 0) + (payslip.other_deductions or 0)
        payslip.net_pay = payslip.gross_pay - payslip.total_deductions

        db.commit()

        return jsonify({
            'success': True,
            'payslip_id': payslip.id,
            'day_column': day_column,
            'day_value': day_value,
            'gross_pay': payslip.gross_pay,
            'net_pay': payslip.net_pay
        })
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# ===== WORKER CLOCK-IN SYSTEM =====

# Configure upload folder for progress pictures
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads', 'progress_pics')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def haversine_distance(lat1, lon1, lat2, lon2):
    """Calculate distance between two GPS coordinates in meters"""
    R = 6371000  # Earth's radius in meters

    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))

    return R * c


def check_gps_any_site(db, latitude, longitude):
    """
    Check if GPS coordinates are within radius of ANY company site.
    Returns (verified, matched_site, distance) tuple.
    Workers can clock in/out at any site, not just their assigned one.
    """
    if not latitude or not longitude:
        return False, None, None

    # Get all sites with GPS coordinates
    sites = db.query(Site).filter(
        Site.gps_latitude != None,
        Site.gps_longitude != None
    ).all()

    best_match = None
    best_distance = None

    for site in sites:
        distance = haversine_distance(
            latitude, longitude,
            site.gps_latitude, site.gps_longitude
        )
        radius = site.gps_radius_meters or 100

        # Track closest site for reporting
        if best_distance is None or distance < best_distance:
            best_distance = distance
            best_match = site

        # If within radius of any site, it's verified
        if distance <= radius:
            return True, site, distance

    # Not within any site radius - return closest for reference
    return False, best_match, best_distance


@app.route('/clockin')
def clockin_page():
    """Serve worker clock-in mobile page"""
    return send_from_directory('templates', 'clockin.html')


@app.route('/api/clockin/worker-login', methods=['POST'])
def worker_login():
    """Worker login using mobile number"""
    db = SessionLocal()
    try:
        data = request.json
        mobile = data.get('mobile', '').strip()

        if not mobile:
            return jsonify({'error': 'Mobile number required'}), 400

        # Normalize mobile - remove spaces, dashes
        mobile_clean = re.sub(r'[\s\-]', '', mobile)

        # Try to find staff by mobile
        staff = db.query(StaffMember).filter(
            StaffMember.mobile.ilike(f'%{mobile_clean[-9:]}%'),  # Match last 9 digits
            StaffMember.is_active == True
        ).first()

        if not staff:
            return jsonify({'error': 'Mobile number not registered'}), 404

        # Generate simple token for worker
        token = jwt.encode({
            'staff_id': staff.id,
            'mobile': mobile_clean,
            'exp': datetime.utcnow() + timedelta(hours=12)
        }, SECRET_KEY, algorithm='HS256')

        # Get site info
        site_info = None
        if staff.site:
            site_info = {
                'id': staff.site.id,
                'name': staff.site.name,
                'latitude': staff.site.gps_latitude,
                'longitude': staff.site.gps_longitude,
                'radius': staff.site.gps_radius_meters or 100
            }

        return jsonify({
            'success': True,
            'token': token,
            'staff': {
                'id': staff.id,
                'name': staff.full_name,
                'position': staff.position
            },
            'site': site_info
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


def worker_token_required(f):
    """Decorator for worker clock-in endpoints"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            db = SessionLocal()
            staff = db.query(StaffMember).filter(StaffMember.id == data['staff_id']).first()

            if not staff:
                db.close()
                return jsonify({'error': 'Worker not found'}), 401

            # Eagerly load site
            if staff.site_id:
                _ = staff.site

            db.close()
            return f(current_staff=staff, *args, **kwargs)

        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

    return decorated


@app.route('/api/clockin/status')
@worker_token_required
def get_clockin_status(current_staff):
    """Get today's clock-in status for worker - supports multiple shifts"""
    db = SessionLocal()
    try:
        today = date.today()

        # Refresh staff to get gps_exempt field
        staff_record = db.query(StaffMember).get( current_staff.id)
        # Admin staff are always GPS exempt
        is_admin = staff_record.employment_type == 'admin'
        is_gps_exempt = getattr(staff_record, 'gps_exempt', False) or False or is_admin

        # Get ALL attendance records for today (multiple shifts)
        attendances = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == current_staff.id,
            WorkerAttendance.work_date == today
        ).order_by(WorkerAttendance.signin_time).all()

        site_info = None
        if current_staff.site_id:
            site = db.query(Site).get(current_staff.site_id)
            if site:
                site_info = {
                    'id': site.id,
                    'name': site.name,
                    'latitude': site.gps_latitude,
                    'longitude': site.gps_longitude,
                    'radius': site.gps_radius_meters or 100
                }

        if attendances:
            # Get the current/latest shift
            current_shift = attendances[-1]

            # Sum up all gross hours worked today
            gross_hours = sum(a.hours_worked or 0 for a in attendances)

            # Calculate net hours after break deductions
            # Break rules: 1hr lunch + 30min tea = 1.5hrs for full day
            BREAK_HOURS = 1.5  # 1hr lunch + 30min tea
            FULL_DAY_THRESHOLD = 9.0  # Gross hours threshold for full break deduction
            HALF_DAY_THRESHOLD = 4.5  # Gross hours threshold for tea break only

            if gross_hours >= FULL_DAY_THRESHOLD:
                # Full day - deduct full 1.5 hours (lunch + tea)
                net_hours = gross_hours - BREAK_HOURS
            elif gross_hours >= HALF_DAY_THRESHOLD:
                # Half day - deduct 30 min tea only
                net_hours = gross_hours - 0.5
            else:
                # Short shift - no break deduction
                net_hours = gross_hours

            # Count pictures across all shifts today
            attendance_ids = [a.id for a in attendances]
            picture_count = db.query(ProgressPicture).filter(
                ProgressPicture.attendance_id.in_(attendance_ids)
            ).count()

            # Build shifts list for display
            shifts = []
            for a in attendances:
                shifts.append({
                    'id': a.id,
                    'signin_time': a.signin_time.isoformat() if a.signin_time else None,
                    'signout_time': a.signout_time.isoformat() if a.signout_time else None,
                    'hours_worked': a.hours_worked,
                    'status': a.status.value
                })

            return jsonify({
                'has_signin': current_shift.signin_time is not None,
                'has_signout': current_shift.signout_time is not None,
                'signin_time': current_shift.signin_time.isoformat() if current_shift.signin_time else None,
                'signout_time': current_shift.signout_time.isoformat() if current_shift.signout_time else None,
                'gps_verified': current_shift.gps_verified,
                'gps_exempt': is_gps_exempt,
                'status': current_shift.status.value,
                'hours_worked': net_hours if net_hours > 0 else current_shift.hours_worked,
                'picture_count': picture_count,
                'site': site_info,
                'staff_name': current_staff.full_name,
                'staff_id': current_staff.id,
                'shift_count': len(attendances),
                'shifts': shifts,
                'can_signin': current_shift.signout_time is not None,  # Can start new shift if last one ended
                'can_signout': current_shift.signin_time is not None and current_shift.signout_time is None
            })

        return jsonify({
            'has_signin': False,
            'has_signout': False,
            'signin_time': None,
            'signout_time': None,
            'gps_verified': False,
            'gps_exempt': is_gps_exempt,
            'status': None,
            'hours_worked': None,
            'picture_count': 0,
            'site': site_info,
            'staff_name': current_staff.full_name,
            'staff_id': current_staff.id,
            'shift_count': 0,
            'shifts': [],
            'can_signin': True,
            'can_signout': False
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/clockin/signin', methods=['POST'])
@worker_token_required
def worker_signin(current_staff):
    """Worker sign-in with GPS verification"""
    db = SessionLocal()
    try:
        data = request.json
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        accuracy = data.get('accuracy')

        today = date.today()
        now = datetime.now()

        # Check for NO-WORK DAY with emergency override
        # Get staff record to check for emergency clock permission
        staff_for_check = db.query(StaffMember).get(current_staff.id)

        # Check if today is a no-work day for this staff member
        no_work_day = db.query(NoWorkDay).filter(
            NoWorkDay.is_active == True,
            NoWorkDay.no_work_date == today,
            or_(
                NoWorkDay.site_id == staff_for_check.site_id,
                NoWorkDay.site_id.is_(None)  # Company-wide
            )
        ).first()

        if no_work_day:
            # Check if staff has emergency clock permission
            if not getattr(staff_for_check, 'allow_emergency_clock', False):
                return jsonify({
                    'error': f'Today ({today.strftime("%d %b %Y")}) is a no-work day: {no_work_day.reason or "Company holiday"}. Contact your manager if you need to work.',
                    'is_no_work_day': True,
                    'reason': no_work_day.reason
                }), 403

        # AUTO-CLEANUP: Close any orphan records from previous days
        # This prevents "already signed in" errors from old incomplete records
        # Rules:
        # 1. No overtime declared + no sign-out = backdate to 16:30 + 20 penalty points
        # 2. Overtime declared but no sign-out = CANCEL overtime, backdate to 16:30 + 20 penalty points
        orphan_records = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == current_staff.id,
            WorkerAttendance.work_date < today,  # From previous days
            WorkerAttendance.signout_time.is_(None)  # Never signed out
        ).all()

        for orphan in orphan_records:
            if orphan.signin_time:
                # Check if overtime was declared
                has_overtime = orphan.overtime_minutes and orphan.overtime_minutes > 0

                # ALL missing sign-outs get backdated to 16:30 with penalty
                # Even if overtime was declared - they should have clocked out!
                orphan.signout_time = datetime.combine(orphan.work_date, datetime.strptime('16:30', '%H:%M').time())

                if has_overtime:
                    # Cancel the overtime since they didn't clock out
                    orphan.overtime_minutes = 0
                    orphan.overtime_reason = None
                    orphan.overtime_confirmed = False
                    orphan.notes = (orphan.notes or '') + ' [AUTO-CLOSED: Overtime CANCELLED - no sign-out - 20 penalty points]'
                else:
                    orphan.notes = (orphan.notes or '') + ' [AUTO-CLOSED: Missing sign-out - 20 penalty points]'

                # Add 20 penalty points - get current pay period
                current_period = db.query(PayPeriod).filter(
                    PayPeriod.status == PayPeriodStatus.OPEN
                ).order_by(PayPeriod.start_date.desc()).first()

                if current_period:
                    penalty = StaffRewardPenalty(
                        staff_id=current_staff.id,
                        pay_period_id=current_period.id,
                        points=-20,
                        category=RewardPenaltyCategory.EARLY_DEPARTURE,
                        source=RewardPenaltySource.SYSTEM,
                        status=RewardPenaltyStatus.APPROVED,
                        description=f'Missing sign-out on {orphan.work_date.strftime("%Y-%m-%d")} - auto-closed',
                        created_by_id=None,
                        approved_by_id=None,
                        approved_at=datetime.now()
                    )
                    db.add(penalty)

                # Calculate hours worked
                orphan.hours_worked = round((orphan.signout_time - orphan.signin_time).total_seconds() / 3600, 2)
                orphan.status = CheckInStatus.COMPLETED
            else:
                # No sign-in time - just delete the orphan
                db.delete(orphan)

        if orphan_records:
            db.commit()
            print(f"[AUTO-CLEANUP] Closed {len(orphan_records)} orphan records for staff {current_staff.id}")

        # Time window check for clock-in (default 07:00 - 07:45, configurable)
        clockin_start = system_config.get('clockin_window_start', '07:00')
        clockin_end = system_config.get('clockin_window_end', '07:45')

        start_hour, start_min = map(int, clockin_start.split(':'))
        end_hour, end_min = map(int, clockin_end.split(':'))

        window_start = now.replace(hour=start_hour, minute=start_min, second=0, microsecond=0)
        window_end = now.replace(hour=end_hour, minute=end_min, second=0, microsecond=0)

        # Check if worker is GPS exempt (they may have flexible hours)
        staff_record = db.query(StaffMember).get( current_staff.id)
        # Admin staff are always GPS exempt
        is_admin = staff_record.employment_type == 'admin'
        is_gps_exempt = getattr(staff_record, 'gps_exempt', False) or False or is_admin

        # Check for override reason (required for late clock-in, but can be any text)
        override_reason = data.get('override_reason', '').strip()

        # Time window enforcement - prompt for reason but allow with any reason
        # Late workers MUST provide a reason (even just "late") to proceed
        if system_config.get('enforce_clockin_window', True) and not is_gps_exempt:
            outside_window = now < window_start or now > window_end
            if outside_window and not override_reason:
                # Prompt for reason - clock-in allowed once reason provided
                if now < window_start:
                    msg = f'Clock-in window starts at {clockin_start}. Please provide a reason.'
                else:
                    msg = f'You are late (window ended at {clockin_end}). Please provide a reason.'
                return jsonify({
                    'error': msg,
                    'window_start': clockin_start,
                    'window_end': clockin_end,
                    'requires_reason': True,
                    'current_time': now.strftime('%H:%M')
                }), 400
            # With reason provided, late clock-ins are allowed - late_minutes recorded

        # Check for existing shifts today - allow multiple shifts
        existing_shifts = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == current_staff.id,
            WorkerAttendance.work_date == today
        ).order_by(WorkerAttendance.signin_time).all()

        # Check if there's an active (uncompleted) shift
        active_shift = None
        for shift in existing_shifts:
            if shift.signin_time and not shift.signout_time:
                active_shift = shift
                break

        if active_shift:
            return jsonify({'error': 'Already signed in - sign out first'}), 400

        # GPS verification against ANY company site (not just assigned site)
        # Workers can clock in at any site location
        distance = None
        gps_verified = is_gps_exempt  # Auto-verified if exempt
        matched_site = None

        if not is_gps_exempt and latitude and longitude:
            # Check against all company sites
            gps_verified, matched_site, distance = check_gps_any_site(db, latitude, longitude)
        elif latitude and longitude:
            # Still calculate distance for records, even if exempt
            _, matched_site, distance = check_gps_any_site(db, latitude, longitude)

        # Calculate late minutes based on expected clock-in time + grace period
        # Expected time is 07:20, grace period is 10 minutes, so late after 07:30
        expected_clockin = system_config.get('expected_clockin_time', '07:20')
        grace_minutes = system_config.get('clockin_grace_minutes', 10)
        exp_hour, exp_min = map(int, expected_clockin.split(':'))
        grace_end = now.replace(hour=exp_hour, minute=exp_min, second=0, microsecond=0) + timedelta(minutes=grace_minutes)

        late_mins = 0
        if now > grace_end:
            late_mins = int((now - grace_end).total_seconds() / 60)

        # Always create a new shift record (multiple shifts per day supported)
        attendance = WorkerAttendance(
            staff_id=current_staff.id,
            site_id=current_staff.site_id,
            work_date=today,
            signin_time=datetime.now(),
            signin_latitude=latitude,
            signin_longitude=longitude,
            signin_accuracy=accuracy,
            signin_distance=distance,
            signin_device=request.headers.get('User-Agent', '')[:500],
            gps_verified=gps_verified,
            status=CheckInStatus.PENDING,
            late_minutes=late_mins,
            notes=f"LATE: {override_reason}" if override_reason and late_mins > 0 else override_reason if override_reason else None
        )
        db.add(attendance)
        db.commit()

        # Update or create attendance reminder with RESPONDED status
        today_reminder = db.query(AttendanceReminder).filter(
            AttendanceReminder.staff_id == current_staff.id,
            AttendanceReminder.work_date == today,
            AttendanceReminder.reminder_type == ReminderType.CLOCKIN
        ).first()
        if today_reminder:
            # Update existing reminder
            today_reminder.status = ReminderStatus.RESPONDED
            today_reminder.responded_at = datetime.now()
            today_reminder.attendance_id = attendance.id
            today_reminder.late_minutes = late_mins  # Update late minutes from actual clock-in
        else:
            # Create a new reminder record marked as responded (for early clock-ins)
            new_reminder = AttendanceReminder(
                staff_id=current_staff.id,
                site_id=current_staff.site_id,
                work_date=today,
                reminder_type=ReminderType.CLOCKIN,
                scheduled_time=datetime.now(),
                status=ReminderStatus.RESPONDED,
                responded_at=datetime.now(),
                attendance_id=attendance.id,
                notes="Clocked in before reminder sent"
            )
            db.add(new_reminder)
        db.commit()

        # Convert standby record to "worked" if this staff has one for today
        # (Standby allowance is replaced by actual work hours)
        try:
            db.execute(
                """UPDATE standby_records
                   SET status = 'worked', worked_at = ?, notes = COALESCE(notes, '') || ' [Converted to worked hours]'
                   WHERE staff_id = ? AND standby_date = ? AND status = 'standby'""",
                (datetime.now().isoformat(), current_staff.id, today)
            )
            db.commit()
        except Exception as standby_err:
            print(f"[STANDBY] Error updating standby record: {standby_err}")

        # Send admin notification SMS (include late info if applicable)
        site = db.query(Site).get(current_staff.site_id) if current_staff.site_id else None
        site_name = site.name if site else 'No Site'
        time_str = attendance.signin_time.strftime('%H:%M')
        if late_mins > 0:
            send_admin_sms(f"LATE SIGNIN: {current_staff.full_name} at {site_name} @ {time_str} ({late_mins}min late) - {override_reason}", 'signin')
        else:
            send_admin_sms(f"SIGNIN: {current_staff.full_name} at {site_name} @ {time_str}", 'signin')

        return jsonify({
            'success': True,
            'message': 'Signed in successfully',
            'signin_time': attendance.signin_time.isoformat(),
            'gps_verified': gps_verified,
            'distance': round(distance, 1) if distance else None,
            'attendance_id': attendance.id
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/clockin/signout', methods=['POST'])
@worker_token_required
def worker_signout(current_staff):
    """Worker sign-out with GPS verification"""
    db = SessionLocal()
    try:
        data = request.json
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        accuracy = data.get('accuracy')

        today = date.today()
        now = datetime.now()

        # Time override - allows worker to specify actual signout time (e.g., for late submissions)
        time_override = data.get('time_override')
        if time_override:
            try:
                # Parse HH:MM format
                override_hour, override_min = map(int, time_override.split(':'))
                now = now.replace(hour=override_hour, minute=override_min, second=0, microsecond=0)
            except (ValueError, AttributeError):
                pass  # Invalid format, use current time

        # Time window check for clock-out (default 16:15 - 16:45, configurable)
        clockout_start = system_config.get('clockout_window_start', '16:15')
        clockout_end = system_config.get('clockout_window_end', '16:45')

        start_hour, start_min = map(int, clockout_start.split(':'))
        end_hour, end_min = map(int, clockout_end.split(':'))

        window_start = now.replace(hour=start_hour, minute=start_min, second=0, microsecond=0)
        window_end = now.replace(hour=end_hour, minute=end_min, second=0, microsecond=0)

        # Check if worker is GPS exempt (they may have flexible hours)
        staff_record = db.query(StaffMember).get( current_staff.id)
        # Admin staff are always GPS exempt
        is_admin = staff_record.employment_type == 'admin'
        is_gps_exempt = getattr(staff_record, 'gps_exempt', False) or False or is_admin

        # Check for override reason (allows early clock-out with explanation)
        override_reason = data.get('override_reason', '').strip()

        # Check for overtime reason (allows late clock-out with explanation)
        overtime_reason = data.get('overtime_reason', '').strip()

        # Project selection (mandatory) and task selection (optional)
        project_id = data.get('project_id')
        project_name = None
        task_id = data.get('task_id')
        task_name = None

        # Look up project name
        if project_id:
            project_result = db.execute(text(
                'SELECT name FROM sync_projects WHERE workpro_id = :project_id'
            ), {'project_id': project_id}).fetchone()
            if project_result:
                project_name = project_result[0]

        # Look up task name if task provided
        if task_id:
            task_result = db.execute(text(
                'SELECT title, project_name FROM sync_tasks WHERE workpro_id = :task_id'
            ), {'task_id': task_id}).fetchone()
            if task_result:
                task_name = f"{task_result[1]}: {task_result[0]}"  # "Project: Task"

        # Enforce time window unless GPS exempt, window check disabled, OR valid reason provided
        if system_config.get('enforce_clockout_window', True) and not is_gps_exempt:
            is_early = now < window_start
            is_late = now > window_end

            # Early clock-out needs override_reason
            if is_early and not override_reason:
                return jsonify({
                    'error': f'Clock-out window is {clockout_start} - {clockout_end}. Provide a reason to override.',
                    'window_start': clockout_start,
                    'window_end': clockout_end,
                    'requires_reason': True,
                    'is_early': True,
                    'current_time': now.strftime('%H:%M')
                }), 400

            # Late clock-out (after window) - ask if working overtime
            if is_late and not overtime_reason:
                overtime_mins = int((now - window_end).total_seconds() / 60)
                return jsonify({
                    'error': f'Clock-out window ended at {clockout_end}. Are you working overtime?',
                    'window_start': clockout_start,
                    'window_end': clockout_end,
                    'requires_overtime_reason': True,
                    'overtime_minutes': overtime_mins,
                    'current_time': now.strftime('%H:%M')
                }), 400

        # Find the active (uncompleted) shift for today
        attendance = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == current_staff.id,
            WorkerAttendance.work_date == today,
            WorkerAttendance.signin_time.isnot(None),
            WorkerAttendance.signout_time.is_(None)
        ).first()

        if not attendance:
            return jsonify({'error': 'No active shift - sign in first'}), 400

        # OVERTIME PICTURE REQUIREMENT: Disabled for now
        # if overtime_reason or attendance.overtime_confirmed:
        #     pic_count = db.query(ProgressPicture).filter(
        #         ProgressPicture.attendance_id == attendance.id
        #     ).count()
        #
        #     if pic_count < 3:
        #         return jsonify({
        #             'error': f'Overtime requires at least 3 progress pictures. You have {pic_count}.',
        #             'requires_pictures': True,
        #             'current_pictures': pic_count,
        #             'required_pictures': 3
        #         }), 400

        # GPS verification against ANY company site (not just assigned site)
        # Workers can clock out at any site location
        distance = None
        if latitude and longitude:
            _, matched_site, distance = check_gps_any_site(db, latitude, longitude)

        # Calculate early departure minutes if before window
        early_mins = 0
        if now < window_start:
            early_mins = int((window_start - now).total_seconds() / 60)

        # Calculate overtime minutes if after window
        overtime_mins = 0
        if now > window_end:
            overtime_mins = int((now - window_end).total_seconds() / 60)

        # Update attendance (use 'now' which may be overridden)
        attendance.signout_time = now
        attendance.signout_latitude = latitude
        attendance.signout_longitude = longitude
        attendance.signout_accuracy = accuracy
        attendance.signout_distance = distance
        attendance.signout_device = request.headers.get('User-Agent', '')[:500]
        attendance.early_departure_minutes = early_mins

        # Store overtime data
        if overtime_reason:
            attendance.overtime_minutes = overtime_mins
            attendance.overtime_reason = overtime_reason
            attendance.overtime_confirmed = True

        # Add reason to notes if early departure or overtime
        if override_reason:
            existing_notes = attendance.notes or ''
            if early_mins > 0:
                attendance.notes = f"{existing_notes} EARLY OUT: {override_reason}".strip()
            else:
                attendance.notes = f"{existing_notes} {override_reason}".strip() if existing_notes else override_reason
        elif overtime_reason:
            existing_notes = attendance.notes or ''
            attendance.notes = f"{existing_notes} OVERTIME: {overtime_reason}".strip()

        # Calculate hours worked
        if attendance.signin_time:
            delta = attendance.signout_time - attendance.signin_time
            attendance.hours_worked = round(delta.total_seconds() / 3600, 2)

        # Update status
        attendance.status = CheckInStatus.COMPLETED

        # Store project/task selection
        if project_id:
            attendance.project_id = project_id
            attendance.project_name = project_name
        if task_id:
            attendance.task_id = task_id
            attendance.task_name = task_name

        db.commit()

        # Calculate net hours for display (after break deductions)
        gross_hours = attendance.hours_worked or 0
        BREAK_HOURS = 1.5  # 1hr lunch + 30min tea
        FULL_DAY_THRESHOLD = 9.0
        HALF_DAY_THRESHOLD = 4.5

        if gross_hours >= FULL_DAY_THRESHOLD:
            net_hours = gross_hours - BREAK_HOURS
        elif gross_hours >= HALF_DAY_THRESHOLD:
            net_hours = gross_hours - 0.5
        else:
            net_hours = gross_hours

        # Send admin notification SMS (include early/overtime info if applicable)
        # Use NET hours (after break deductions) in SMS
        site = db.query(Site).get(current_staff.site_id) if current_staff.site_id else None
        site_name = site.name if site else 'No Site'
        time_str = attendance.signout_time.strftime('%H:%M')
        display_hours = round(net_hours, 2)
        if early_mins > 0:
            send_admin_sms(f"EARLY SIGNOUT: {current_staff.full_name} at {site_name} @ {time_str} ({display_hours}hrs, {early_mins}min early) - {override_reason}", 'signout')
        elif overtime_reason:
            send_admin_sms(f"OVERTIME SIGNOUT: {current_staff.full_name} at {site_name} @ {time_str} ({display_hours}hrs, {overtime_mins}min OT) - {overtime_reason}", 'signout')
        else:
            send_admin_sms(f"SIGNOUT: {current_staff.full_name} at {site_name} @ {time_str} ({display_hours}hrs)", 'signout')

        return jsonify({
            'success': True,
            'message': 'Signed out successfully',
            'signout_time': attendance.signout_time.isoformat(),
            'hours_worked': round(net_hours, 2),  # Net hours for display (after break deductions)
            'distance': round(distance, 1) if distance else None,
            'attendance_id': attendance.id  # For overtime photo upload
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/clockin/leave', methods=['POST'])
@worker_token_required
def worker_submit_leave(current_staff):
    """Worker submits leave (L or S) for today"""
    db = SessionLocal()
    try:
        data = request.json
        leave_type_str = data.get('leave_type', 'S')  # Default to Sick
        reason = data.get('reason', '').strip()

        today = date.today()

        # Check if already clocked in today
        existing_attendance = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == current_staff.id,
            WorkerAttendance.work_date == today,
            WorkerAttendance.signin_time.isnot(None)
        ).first()

        if existing_attendance:
            return jsonify({'error': 'Already clocked in today - cannot mark as leave'}), 400

        # Check if leave already exists for today
        existing_leave = db.query(LeaveRecord).filter(
            LeaveRecord.staff_id == current_staff.id,
            LeaveRecord.leave_date == today,
            LeaveRecord.status != LeaveStatus.CANCELLED
        ).first()

        if existing_leave:
            return jsonify({
                'error': f'Leave already recorded for today ({existing_leave.leave_type.value})',
                'leave_type': existing_leave.leave_type.value
            }), 400

        # Create leave record
        leave_type = LeaveType.BOOKED if leave_type_str == 'L' else LeaveType.SICK

        leave_record = LeaveRecord(
            staff_id=current_staff.id,
            site_id=current_staff.site_id,
            leave_date=today,
            leave_type=leave_type,
            status=LeaveStatus.APPROVED,  # Auto-approved when entered by worker
            reason=reason,
            notes=f"Entered by worker via clock-in page"
        )
        db.add(leave_record)
        db.commit()

        # Send admin notification SMS
        site = db.query(Site).get(current_staff.site_id) if current_staff.site_id else None
        site_name = site.name if site else 'No Site'
        leave_label = 'BOOKED LEAVE' if leave_type == LeaveType.BOOKED else 'SICK LEAVE'
        reason_text = f' - {reason}' if reason else ''
        send_admin_sms(f"{leave_label}: {current_staff.full_name} at {site_name}{reason_text}", 'leave')

        return jsonify({
            'success': True,
            'message': f'{leave_label} recorded successfully',
            'leave_type': leave_type.value,
            'leave_date': today.isoformat()
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/clockin/leave-status', methods=['GET'])
@worker_token_required
def worker_check_leave_status(current_staff):
    """Check if worker has leave recorded for today"""
    db = SessionLocal()
    try:
        today = date.today()

        # Check for leave today
        leave = db.query(LeaveRecord).filter(
            LeaveRecord.staff_id == current_staff.id,
            LeaveRecord.leave_date == today,
            LeaveRecord.status != LeaveStatus.CANCELLED
        ).first()

        if leave:
            return jsonify({
                'on_leave': True,
                'leave_type': leave.leave_type.value,
                'leave_label': 'Booked Leave' if leave.leave_type == LeaveType.BOOKED else 'Sick Leave',
                'reason': leave.reason
            })

        # Also check for attendance
        attendance = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == current_staff.id,
            WorkerAttendance.work_date == today
        ).first()

        return jsonify({
            'on_leave': False,
            'has_attendance': attendance is not None,
            'signed_in': attendance.signin_time is not None if attendance else False,
            'signed_out': attendance.signout_time is not None if attendance else False
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/clockin/not-working', methods=['POST'])
@worker_token_required
def worker_not_working(current_staff):
    """Worker confirms they are NOT working today

    This provides a positive response to clock-in reminders when worker
    is not coming to work (for reasons other than leave).
    Records GPS location for verification.
    """
    db = SessionLocal()
    try:
        data = request.json
        reason = data.get('reason', '').strip()
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        accuracy = data.get('accuracy')

        if not reason:
            return jsonify({'error': 'Please provide a reason'}), 400

        today = date.today()
        now = datetime.now()
        was_clock_in_override = False  # Track if we're overriding a clock-in

        # Check if already clocked in today
        existing_attendance = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == current_staff.id,
            WorkerAttendance.work_date == today,
            WorkerAttendance.signin_time.isnot(None)
        ).first()

        # Allow NOT WORKING to override clock-in if less than 2 hours worked
        if existing_attendance:
            if existing_attendance.signout_time:
                # Already completed - can't override
                return jsonify({'error': 'Already completed a shift today'}), 400

            # Calculate hours since sign-in
            hours_since_signin = (now - existing_attendance.signin_time).total_seconds() / 3600

            if hours_since_signin >= 2:
                return jsonify({
                    'error': f'Already worked {hours_since_signin:.1f} hours - too late to cancel. Use Sign Out instead.'
                }), 400

            # Less than 2 hours - allow override: delete the attendance record
            was_clock_in_override = True
            db.delete(existing_attendance)
            db.commit()
            # Continue to record NOT WORKING status

        # Check if on leave today (shouldn't need this option)
        existing_leave = db.query(LeaveRecord).filter(
            LeaveRecord.staff_id == current_staff.id,
            LeaveRecord.leave_date == today,
            LeaveRecord.status != LeaveStatus.CANCELLED
        ).first()

        if existing_leave:
            return jsonify({
                'error': f'Already marked as on leave today ({existing_leave.leave_type.value})'
            }), 400

        # Update or create attendance reminder with NOT_WORKING status
        today_reminder = db.query(AttendanceReminder).filter(
            AttendanceReminder.staff_id == current_staff.id,
            AttendanceReminder.work_date == today,
            AttendanceReminder.reminder_type == ReminderType.CLOCKIN
        ).first()

        gps_info = ""
        if latitude and longitude:
            gps_info = f" @ {latitude:.6f},{longitude:.6f}"
            if accuracy:
                gps_info += f" (±{accuracy:.0f}m)"

        if today_reminder:
            # Update existing reminder
            today_reminder.status = ReminderStatus.NOT_WORKING
            today_reminder.responded_at = now
            today_reminder.notes = f"NOT WORKING: {reason}{gps_info}"
        else:
            # Create a new reminder record
            new_reminder = AttendanceReminder(
                staff_id=current_staff.id,
                site_id=current_staff.site_id,
                work_date=today,
                reminder_type=ReminderType.CLOCKIN,
                scheduled_time=now,
                status=ReminderStatus.NOT_WORKING,
                responded_at=now,
                notes=f"NOT WORKING: {reason}{gps_info}"
            )
            db.add(new_reminder)

        db.commit()

        # Send admin notification SMS
        site = db.query(Site).get(current_staff.site_id) if current_staff.site_id else None
        site_name = site.name if site else 'No Site'
        time_str = now.strftime('%H:%M')

        # Build SMS message
        override_note = " (CANCELLED CLOCK-IN)" if was_clock_in_override else ""
        if latitude and longitude:
            sms_msg = f"NOT WORKING{override_note}: {current_staff.full_name} ({site_name}) @ {time_str} - {reason} maps.google.com/?q={latitude},{longitude}"
        else:
            sms_msg = f"NOT WORKING{override_note}: {current_staff.full_name} ({site_name}) @ {time_str} - {reason}"

        send_admin_sms(sms_msg, 'not_working')

        return jsonify({
            'success': True,
            'message': 'Clock-in cancelled and marked as not working' if was_clock_in_override else 'Response recorded successfully',
            'responded_at': now.isoformat(),
            'was_override': was_clock_in_override
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/clockin/still-working', methods=['POST'])
@worker_token_required
def worker_still_working(current_staff):
    """Worker indicates they are working overtime (proactive notification)

    This allows workers to proactively notify admin that they're working late,
    rather than just ignoring the clock-out reminder. Admin gets SMS notification.
    """
    db = SessionLocal()
    try:
        data = request.json
        reason = data.get('reason', '').strip()

        if not reason:
            return jsonify({'error': 'Please provide a reason for overtime'}), 400

        today = date.today()
        now = datetime.now()

        # Check if worker is currently clocked in
        attendance = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == current_staff.id,
            WorkerAttendance.work_date == today,
            WorkerAttendance.signin_time.isnot(None),
            WorkerAttendance.signout_time.is_(None)
        ).first()

        if not attendance:
            return jsonify({'error': 'You must be clocked in to indicate overtime'}), 400

        # Already indicated overtime?
        if attendance.overtime_confirmed:
            return jsonify({'error': 'Overtime already indicated for today'}), 400

        # Mark as overtime (pre-emptive)
        attendance.overtime_confirmed = True
        attendance.overtime_reason = reason
        attendance.notes = (attendance.notes or '') + f"\nProactive OT notification at {now.strftime('%H:%M')}: {reason}"

        db.commit()

        # Send admin notification SMS
        site = db.query(Site).get(current_staff.site_id) if current_staff.site_id else None
        site_name = site.name if site else 'No Site'
        time_str = now.strftime('%H:%M')

        send_admin_sms(
            f"OVERTIME: {current_staff.full_name} still working at {site_name} @ {time_str} - {reason}",
            'overtime'
        )

        # Schedule a reminder SMS to the worker in 2 hours if they haven't clocked out
        # This is done by storing the overtime start time and checking on status requests
        # The actual reminder logic is in the /api/clockin/status endpoint

        return jsonify({
            'success': True,
            'message': 'Admin notified of overtime. REMEMBER: You must clock out when done!',
            'reason': reason,
            'warning': 'If you do not clock out, overtime will be cancelled and you will receive 20 penalty points.'
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/clockin/upload-picture', methods=['POST'])
@worker_token_required
def upload_progress_picture(current_staff):
    """Upload a progress picture"""
    db = SessionLocal()
    try:
        today = date.today()

        # Get today's attendance
        attendance = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == current_staff.id,
            WorkerAttendance.work_date == today
        ).first()

        if not attendance or not attendance.signin_time:
            return jsonify({'error': 'Must sign in first'}), 400

        if 'picture' not in request.files:
            return jsonify({'error': 'No picture provided'}), 400

        file = request.files['picture']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Use JPG, PNG, GIF, or WEBP'}), 400

        # Get GPS data from form
        latitude = request.form.get('latitude', type=float)
        longitude = request.form.get('longitude', type=float)
        accuracy = request.form.get('accuracy', type=float)
        description = request.form.get('description', '')

        # Generate unique filename
        ext = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{current_staff.id}_{today.isoformat()}_{uuid.uuid4().hex[:8]}.{ext}"

        # Create date-based subfolder
        date_folder = os.path.join(app.config['UPLOAD_FOLDER'], today.isoformat())
        os.makedirs(date_folder, exist_ok=True)

        file_path = os.path.join(date_folder, unique_filename)
        file.save(file_path)

        # Get file size
        file_size = os.path.getsize(file_path)

        # Create picture record
        picture = ProgressPicture(
            attendance_id=attendance.id,
            staff_id=current_staff.id,
            site_id=current_staff.site_id,
            filename=unique_filename,
            original_filename=secure_filename(file.filename),
            file_path=file_path,
            file_size=file_size,
            taken_at=datetime.now(),
            latitude=latitude,
            longitude=longitude,
            accuracy=accuracy,
            description=description,
            status=PictureStatus.PENDING
        )
        db.add(picture)
        db.commit()

        # Count pictures for today
        picture_count = db.query(ProgressPicture).filter(
            ProgressPicture.attendance_id == attendance.id
        ).count()

        return jsonify({
            'success': True,
            'message': 'Picture uploaded',
            'picture_id': picture.id,
            'picture_count': picture_count
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/clockin/pictures')
@worker_token_required
def get_worker_pictures(current_staff):
    """Get today's pictures for worker"""
    db = SessionLocal()
    try:
        today = date.today()

        attendance = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == current_staff.id,
            WorkerAttendance.work_date == today
        ).first()

        if not attendance:
            return jsonify({'pictures': []})

        pictures = db.query(ProgressPicture).filter(
            ProgressPicture.attendance_id == attendance.id
        ).order_by(ProgressPicture.taken_at.desc()).all()

        return jsonify({
            'pictures': [{
                'id': p.id,
                'filename': p.filename,
                'taken_at': p.taken_at.isoformat(),
                'status': p.status.value,
                'description': p.description
            } for p in pictures]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/clockin/tasks')
@worker_token_required
def get_tasks_for_signout(current_staff):
    """Get synced projects/tasks for sign-out dropdown"""
    db = SessionLocal()
    try:
        # Check if staff is a manager (can create projects/tasks)
        staff = db.query(StaffMember).get(current_staff.id)
        position = (staff.position or '').upper() if staff else ''
        is_manager = 'MANAGER' in position or 'CEO' in position or 'DIRECTOR' in position

        # Query sync_projects table (synced from WORKPRO)
        projects_result = db.execute(text('''
            SELECT workpro_id, name, code, status
            FROM sync_projects
            WHERE status IN ('ACTIVE', 'IN_PROGRESS')
            ORDER BY name
        ''')).fetchall()

        # Query sync_tasks table (synced from WORKPRO)
        tasks_result = db.execute(text('''
            SELECT workpro_id, project_id, project_name, title, status
            FROM sync_tasks
            WHERE status != 'CANCELLED'
            ORDER BY project_name, title
        ''')).fetchall()

        projects = [{
            'id': p[0],
            'name': p[1],
            'code': p[2],
            'status': p[3]
        } for p in projects_result]

        tasks = [{
            'id': t[0],
            'project_id': t[1],
            'project_name': t[2],
            'title': t[3],
            'status': t[4]
        } for t in tasks_result]

        return jsonify({
            'projects': projects,
            'tasks': tasks,
            'is_manager': is_manager,
            'staff_position': staff.position if staff else None
        })

    except Exception as e:
        # Tables might not exist yet if sync hasn't run
        import traceback
        print(f"Error in get_tasks_for_signout: {str(e)}")
        print(traceback.format_exc())
        return jsonify({
            'projects': [],
            'tasks': [],
            'is_manager': False,
            'error': str(e)
        })
    finally:
        db.close()


@app.route('/api/clockin/create-project', methods=['POST'])
@worker_token_required
def create_quick_project(current_staff):
    """Create a new project on the fly (managers only)"""
    db = SessionLocal()
    try:
        # Check if staff is a manager
        staff = db.query(StaffMember).get(current_staff.id)
        position = (staff.position or '').upper() if staff else ''
        is_manager = 'MANAGER' in position or 'CEO' in position or 'DIRECTOR' in position

        if not is_manager:
            return jsonify({'error': 'Only managers can create projects'}), 403

        data = request.json
        project_name = data.get('name', '').strip()
        if not project_name:
            return jsonify({'error': 'Project name is required'}), 400

        # Get max workpro_id for local projects (use negative to avoid conflicts with WORKPRO sync)
        max_id_result = db.execute(text('SELECT MIN(workpro_id) FROM sync_projects')).fetchone()
        next_id = min((max_id_result[0] or 0) - 1, -1)  # Local projects use negative IDs

        # Insert new project
        db.execute(text('''
            INSERT INTO sync_projects (workpro_id, name, code, status, synced_at)
            VALUES (:id, :name, :code, 'ACTIVE', :synced_at)
        '''), {
            'id': next_id,
            'name': project_name.upper(),
            'code': project_name[:10].upper().replace(' ', ''),
            'synced_at': datetime.now().isoformat()
        })
        db.commit()

        return jsonify({
            'success': True,
            'project': {
                'id': next_id,
                'name': project_name.upper(),
                'code': project_name[:10].upper().replace(' ', ''),
                'status': 'ACTIVE'
            }
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/clockin/create-task', methods=['POST'])
@worker_token_required
def create_quick_task(current_staff):
    """Create a new task for a project on the fly (managers only)"""
    db = SessionLocal()
    try:
        # Check if staff is a manager
        staff = db.query(StaffMember).get(current_staff.id)
        position = (staff.position or '').upper() if staff else ''
        is_manager = 'MANAGER' in position or 'CEO' in position or 'DIRECTOR' in position

        if not is_manager:
            return jsonify({'error': 'Only managers can create tasks'}), 403

        data = request.json
        task_name = data.get('name', '').strip()
        project_id = data.get('project_id')

        if not task_name:
            return jsonify({'error': 'Task name is required'}), 400
        if not project_id:
            return jsonify({'error': 'Project ID is required'}), 400

        # Get project name
        project_result = db.execute(text(
            'SELECT name FROM sync_projects WHERE workpro_id = :id'
        ), {'id': project_id}).fetchone()

        if not project_result:
            return jsonify({'error': 'Project not found'}), 404

        project_name = project_result[0]

        # Get max workpro_id for local tasks (use negative to avoid conflicts)
        max_id_result = db.execute(text('SELECT MIN(workpro_id) FROM sync_tasks')).fetchone()
        next_id = min((max_id_result[0] or 0) - 1, -1)

        # Insert new task
        db.execute(text('''
            INSERT INTO sync_tasks (workpro_id, project_id, project_name, title, status, synced_at)
            VALUES (:id, :project_id, :project_name, :title, 'IN_PROGRESS', :synced_at)
        '''), {
            'id': next_id,
            'project_id': project_id,
            'project_name': project_name,
            'title': task_name.upper(),
            'synced_at': datetime.now().isoformat()
        })
        db.commit()

        return jsonify({
            'success': True,
            'task': {
                'id': next_id,
                'project_id': project_id,
                'project_name': project_name,
                'title': task_name.upper(),
                'status': 'IN_PROGRESS'
            }
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/uploads/progress_pics/<path:filename>')
def serve_progress_pic(filename):
    """Serve uploaded progress pictures"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ===== WHEREABOUTS / LOCATION CHECK =====

# Public URL for location links (update when using ngrok)
PUBLIC_URL = "https://wagepro.ngrok.app"  # ngrok HTTPS tunnel (reserved domain)

# Admin notification settings
ADMIN_MOBILE = "0826000859"  # System admin mobile for notifications

# System config (for admin SMS notifications and settings)
system_config = {
    'admin_name': 'Bruce',
    'admin_email': '',
    'admin_mobile': '0826000859',
    'company_name': 'Levendig',
    'public_url': PUBLIC_URL,
    'notify_signin': True,
    'notify_signout': True,
    'notify_location': True,
    # Attendance reminder settings
    'reminder_enabled': True,
    'clockin_time': '07:20',
    'clockin_grace_minutes': 10,
    'clockout_time': '16:30',
    'clockout_window_minutes': 10,
    'notify_late_clockin': True,
    'notify_missed_clockout': True,
    # Clock-in/out time window restrictions (prevents gaming the system)
    'enforce_clockin_window': True,
    'clockin_window_start': '07:00',
    'clockin_window_end': '09:00',
    'enforce_clockout_window': True,
    'clockout_window_start': '16:15',
    'clockout_window_end': '16:45',
    # Standby allowance for no-work days (fixed daily rate in Rands)
    'standby_daily_rate': 150.00
}


def send_admin_sms(message, notification_type='other'):
    """Send SMS notification to system admin
    notification_type: 'signin', 'signout', 'location', or 'other'
    """
    try:
        # Check if this notification type is enabled
        if notification_type == 'signin' and not system_config.get('notify_signin', True):
            print(f"[ADMIN SMS] Skipped (signin notifications disabled)")
            return False
        if notification_type == 'signout' and not system_config.get('notify_signout', True):
            print(f"[ADMIN SMS] Skipped (signout notifications disabled)")
            return False
        if notification_type == 'location' and not system_config.get('notify_location', True):
            print(f"[ADMIN SMS] Skipped (location notifications disabled)")
            return False

        notifier = SMSNotifier()
        messages = [{'mobile': ADMIN_MOBILE, 'message': message}]
        batch_file = notifier.create_batch_file(messages)
        if batch_file:
            success, status = notifier.upload_to_winsms(batch_file)
            print(f"[ADMIN SMS] {status}: {message[:50]}...")
            return success
    except Exception as e:
        print(f"[ADMIN SMS ERROR] {e}")
    return False


@app.route('/locate/<token>')
def locate_page(token):
    """Serve the location sharing page"""
    db = SessionLocal()
    try:
        # Debug: Log the token being searched
        print(f"[LOCATE] Looking for token: {token}")

        # Find the location request by token
        loc_req = db.query(LocationRequest).filter(
            LocationRequest.token == token
        ).first()

        # Debug: Log result
        print(f"[LOCATE] Found: {loc_req is not None}")
        if loc_req:
            print(f"[LOCATE] ID: {loc_req.id}, Status: {loc_req.status}")

        if not loc_req:
            return render_template('locate.html',
                staff_name='Unknown',
                token=token,
                reason='',
                expired=True
            )

        # Check if expired - compare status by name to handle DB storing uppercase
        is_exp = loc_req.is_expired
        # Handle both enum object and string from DB
        if hasattr(loc_req.status, 'name'):
            status_is_pending = loc_req.status.name == 'PENDING'
        else:
            status_is_pending = str(loc_req.status).upper() == 'PENDING'
        expired = is_exp or not status_is_pending

        # Debug logging
        print(f"[LOCATE DEBUG] Token: {token[:20]}...")
        print(f"[LOCATE DEBUG] is_expired: {is_exp}, status: {loc_req.status}, status_is_pending: {status_is_pending}")
        print(f"[LOCATE DEBUG] expires_at: {loc_req.expires_at}, now: {datetime.now()}")
        print(f"[LOCATE DEBUG] FINAL expired={expired}")

        # Get staff name
        staff = db.query(StaffMember).get(loc_req.staff_id)
        staff_name = staff.full_name if staff else 'Staff Member'

        response = make_response(render_template('locate.html',
            staff_name=staff_name,
            token=token,
            reason=loc_req.reason or 'Whereabouts check requested',
            expired=expired,
            sent_time=loc_req.requested_at.strftime('%H:%M:%S') if loc_req.requested_at else 'N/A',
            expires_time=loc_req.expires_at.strftime('%H:%M:%S') if loc_req.expires_at else 'N/A',
            server_time=datetime.now().strftime('%H:%M:%S'),
            status_debug=f"{loc_req.status} (is_expired={is_exp}, status_is_pending={status_is_pending})"
        ))
        # Prevent caching - always fetch fresh
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    except Exception as e:
        print(f"[LOCATE EXCEPTION] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return render_template('locate.html',
            staff_name='Error',
            token=token,
            reason=str(e),
            expired=True,
            sent_time='ERR',
            expires_time='ERR',
            server_time=datetime.now().strftime('%H:%M:%S'),
            status_debug=f"EXCEPTION: {type(e).__name__}: {e}"
        )
    finally:
        db.close()


@app.route('/api/location/request', methods=['POST'])
@token_required
def send_location_request(current_user):
    """Send SMS with location request link to a staff member"""
    db = SessionLocal()
    try:
        data = request.json
        staff_id = data.get('staff_id')
        reason = data.get('reason', 'Whereabouts check')

        if not staff_id:
            return jsonify({'error': 'staff_id is required'}), 400

        # Get staff member
        staff = db.query(StaffMember).get(staff_id)
        if not staff:
            return jsonify({'error': 'Staff member not found'}), 404

        # Get mobile number
        mobile = staff.mobile or staff.phone
        if not mobile:
            return jsonify({'error': 'Staff member has no mobile number'}), 400

        # Generate unique token
        token = secrets.token_urlsafe(32)

        # Create location request record
        loc_req = LocationRequest(
            staff_id=staff_id,
            token=token,
            requested_at=datetime.now(),
            requested_by=current_user.username,
            reason=reason,
            expires_at=datetime.now() + timedelta(minutes=20)
        )
        db.add(loc_req)
        db.commit()

        # Build location link
        location_link = f"{PUBLIC_URL}/locate/{token}"

        # Send SMS
        sms_message = f"WAGEPRO: {reason}. Click to share your location: {location_link}"

        notifier = SMSNotifier()
        messages = [{'mobile': mobile, 'message': sms_message}]
        batch_file = notifier.create_batch_file(messages)

        if batch_file:
            success, msg = notifier.upload_to_winsms(batch_file)
            loc_req.sms_sent_at = datetime.now()
            loc_req.sms_status = 'sent' if success else 'failed'

            # Log SMS to database
            if success:
                import os
                log_sms(
                    db=db,
                    staff_id=staff_id,
                    phone_number=mobile,
                    message=sms_message,
                    sms_type=SMSType.LOCATION_CHECK,
                    batch_filename=os.path.basename(batch_file),
                    sent_by_id=current_user.id
                )

            db.commit()

            if success:
                return jsonify({
                    'success': True,
                    'message': f'Location request SMS sent to {staff.full_name}',
                    'request_id': loc_req.id,
                    'link': location_link
                })
            else:
                return jsonify({'error': f'SMS send failed: {msg}'}), 500
        else:
            return jsonify({'error': 'Failed to create SMS batch'}), 500

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/location/receive', methods=['POST'])
def receive_location():
    """Receive GPS location from staff (called from locate.html)"""
    db = SessionLocal()
    try:
        data = request.json
        token = data.get('token')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        accuracy = data.get('accuracy')

        if not token:
            return jsonify({'error': 'Token is required'}), 400

        # Find the location request
        loc_req = db.query(LocationRequest).filter(
            LocationRequest.token == token
        ).first()

        if not loc_req:
            return jsonify({'error': 'Invalid token'}), 404

        if loc_req.is_expired:
            return jsonify({'error': 'This link has expired'}), 400

        if loc_req.status != LocationRequestStatus.PENDING:
            return jsonify({'error': 'Location already received'}), 400

        # Update with location data
        loc_req.latitude = latitude
        loc_req.longitude = longitude
        loc_req.accuracy = accuracy
        loc_req.responded_at = datetime.now()
        loc_req.status = LocationRequestStatus.RECEIVED

        db.commit()

        # Get staff name for response
        staff = db.query(StaffMember).get(loc_req.staff_id)
        staff_name = staff.full_name if staff else 'Staff'

        # Send admin notification SMS with location
        maps_link = f"maps.google.com/?q={latitude},{longitude}"
        send_admin_sms(f"LOCATE: {staff_name} @ {latitude:.4f},{longitude:.4f} - {maps_link}", 'location')

        return jsonify({
            'success': True,
            'message': f'Location received from {staff_name}',
            'latitude': latitude,
            'longitude': longitude
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/location/requests')
@token_required
def list_location_requests(current_user):
    """List recent location requests"""
    db = SessionLocal()
    try:
        # Get today's requests only
        today_start = datetime.combine(date.today(), datetime.min.time())
        requests = db.query(LocationRequest).filter(
            LocationRequest.requested_at >= today_start
        ).order_by(LocationRequest.requested_at.desc()).all()

        result = []
        for req in requests:
            staff = db.query(StaffMember).get(req.staff_id)
            staff_phone = (staff.mobile or staff.phone or '') if staff else ''
            result.append({
                'id': req.id,
                'staff_name': staff.full_name if staff else 'Unknown',
                'staff_phone': staff_phone,
                'staff_id': req.staff_id,
                'requested_at': req.requested_at.strftime('%d/%m %H:%M') if req.requested_at else None,
                'requested_by': req.requested_by,
                'reason': req.reason,
                'status': req.status.value,
                'responded_at': req.responded_at.strftime('%d/%m %H:%M') if req.responded_at else None,
                'latitude': req.latitude,
                'longitude': req.longitude,
                'accuracy': req.accuracy,
                'google_maps_link': f"https://www.google.com/maps?q={req.latitude},{req.longitude}" if req.latitude else None
            })

        return jsonify({'requests': result})

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/location/test', methods=['POST'])
def test_location_sms():
    """Quick test - send location request to specified mobile number (no auth for testing)"""
    db = SessionLocal()
    try:
        data = request.json
        mobile = data.get('mobile', '0826000859')  # Default to Bruce's number
        reason = data.get('reason', 'WAGEPRO Test - Whereabouts check')

        # Find staff by mobile or create test entry
        staff = db.query(StaffMember).filter(
            (StaffMember.mobile == mobile) | (StaffMember.phone == mobile)
        ).first()

        if not staff:
            # Use first staff member with that mobile pattern
            staff = db.query(StaffMember).filter(
                StaffMember.mobile.like(f'%{mobile[-6:]}%')
            ).first()

        if not staff:
            return jsonify({'error': f'No staff found with mobile {mobile}'}), 404

        # Generate unique token
        token = secrets.token_urlsafe(32)

        # Create location request record
        loc_req = LocationRequest(
            staff_id=staff.id,
            token=token,
            requested_at=datetime.now(),
            requested_by='TEST',
            reason=reason,
            expires_at=datetime.now() + timedelta(minutes=20)
        )
        db.add(loc_req)
        db.commit()

        # Build location link
        location_link = f"{PUBLIC_URL}/locate/{token}"

        # Send SMS
        sms_message = f"WAGEPRO: {reason}. Click to share your location: {location_link}"

        notifier = SMSNotifier()
        messages = [{'mobile': mobile, 'message': sms_message}]
        batch_file = notifier.create_batch_file(messages)

        if batch_file:
            success, msg = notifier.upload_to_winsms(batch_file)
            loc_req.sms_sent_at = datetime.now()
            loc_req.sms_status = 'sent' if success else 'failed'
            db.commit()

            return jsonify({
                'success': success,
                'message': f'SMS sent to {staff.full_name} ({mobile})',
                'sms_status': msg,
                'link': location_link,
                'request_id': loc_req.id
            })
        else:
            return jsonify({'error': 'Failed to create SMS batch'}), 500

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# ===== TRACKING API =====

@app.route('/api/tracking/today')
@token_required
def get_tracking_today(current_user):
    """Get today's staff tracking summary"""
    db = SessionLocal()
    try:
        today = date.today()

        # Get all attendance records for today
        attendances = db.query(WorkerAttendance).filter(
            WorkerAttendance.work_date == today
        ).all()

        # Get all active staff
        all_staff = db.query(StaffMember).filter(
            StaffMember.is_active == True
        ).all()

        # Group attendance records by staff_id to handle multiple sessions
        staff_sessions = {}
        for att in attendances:
            if att.staff_id not in staff_sessions:
                staff_sessions[att.staff_id] = []
            staff_sessions[att.staff_id].append(att)

        signed_in = []
        completed = []
        signed_in_staff_ids = set()
        total_hours = 0
        total_value = 0  # Total Rand value of hours worked

        for staff_id, sessions in staff_sessions.items():
            staff = db.query(StaffMember).get(staff_id)
            # Hourly rate: use hourly_rate if set, otherwise daily_rate / 8
            if staff:
                hourly_rate = staff.hourly_rate or (staff.daily_rate / 8 if staff.daily_rate else 0)
            else:
                hourly_rate = 0

            # Calculate total hours across all sessions
            staff_total_hours = 0
            current_session = None
            first_signin_time = None
            any_gps_verified = False
            site = None

            for att in sessions:
                if site is None and att.site_id:
                    site = db.query(Site).get(att.site_id)
                any_gps_verified = any_gps_verified or (att.gps_verified or False)

                if att.signin_time:
                    if first_signin_time is None or att.signin_time < first_signin_time:
                        first_signin_time = att.signin_time

                    if att.signout_time:
                        # Completed session
                        staff_total_hours += att.hours_worked or 0
                    else:
                        # Currently signed in - this is the active session
                        current_session = att
                        current_hours = (datetime.now() - att.signin_time).total_seconds() / 3600
                        staff_total_hours += current_hours

            if current_session:
                # Staff is currently signed in
                signed_in.append({
                    'staff_id': staff_id,
                    'staff_name': staff.full_name if staff else 'Unknown',
                    'site_name': site.name if site else None,
                    'signin_time': current_session.signin_time.strftime('%H:%M'),
                    'hours_so_far': round(staff_total_hours, 2),  # Sum of all sessions
                    'gps_verified': any_gps_verified
                })
                signed_in_staff_ids.add(staff_id)
            else:
                # All sessions completed - show last session in completed list
                last_session = max(sessions, key=lambda x: x.signout_time or datetime.min)
                completed.append({
                    'staff_id': staff_id,
                    'staff_name': staff.full_name if staff else 'Unknown',
                    'site_name': site.name if site else None,
                    'signin_time': first_signin_time.strftime('%H:%M') if first_signin_time else '--:--',
                    'signout_time': last_session.signout_time.strftime('%H:%M') if last_session.signout_time else '--:--',
                    'hours_worked': round(staff_total_hours, 2),  # Sum of all sessions
                    'gps_verified': any_gps_verified
                })
                signed_in_staff_ids.add(staff_id)

            total_hours += staff_total_hours
            total_value += staff_total_hours * hourly_rate
            print(f"DEBUG: {staff.full_name if staff else 'Unknown'}: {staff_total_hours:.2f}h x R{hourly_rate:.2f} = R{staff_total_hours * hourly_rate:.2f}")

        print(f"DEBUG TOTAL: {total_hours:.2f}h = R{total_value:.2f}")
        # Get staff on leave today (to exclude from not_signed_in)
        staff_on_leave_ids = set()
        leave_records = db.query(LeaveRecord).filter(
            LeaveRecord.leave_date == today,
            LeaveRecord.status != LeaveStatus.CANCELLED
        ).all()
        for lr in leave_records:
            staff_on_leave_ids.add(lr.staff_id)

        # Get staff who confirmed NOT WORKING today
        not_working_staff = []
        not_working_staff_ids = set()
        not_working_reminders = db.query(AttendanceReminder).filter(
            AttendanceReminder.work_date == today,
            AttendanceReminder.status == ReminderStatus.NOT_WORKING
        ).all()
        for reminder in not_working_reminders:
            staff = db.query(StaffMember).get(reminder.staff_id)
            if staff:
                site = db.query(Site).get(staff.site_id) if staff.site_id else None
                # Parse notes to get reason
                reason = "Not working"
                if reminder.notes:
                    # Notes format: "NOT WORKING: reason | GPS: lat,lng (acc: Xm)"
                    if reminder.notes.startswith("NOT WORKING: "):
                        parts = reminder.notes.split(" | GPS:")
                        reason = parts[0].replace("NOT WORKING: ", "")
                not_working_staff.append({
                    'id': staff.id,
                    'full_name': staff.full_name,
                    'site_name': site.name if site else None,
                    'reason': reason,
                    'time': reminder.first_sms_sent_at.strftime('%H:%M') if reminder.first_sms_sent_at else '--:--'
                })
                not_working_staff_ids.add(staff.id)

        # Check if today is a no-work day (for emergency column display)
        is_no_work_day = db.query(NoWorkDay).filter(
            NoWorkDay.is_active == True,
            NoWorkDay.no_work_date == today
        ).first() is not None

        # Get staff not signed in today (with details)
        # Exclude staff who are on leave OR confirmed not working
        not_signed_in = []
        for s in all_staff:
            if s.id not in signed_in_staff_ids and s.id not in staff_on_leave_ids and s.id not in not_working_staff_ids:
                site = db.query(Site).get(s.site_id) if s.site_id else None
                not_signed_in.append({
                    'id': s.id,
                    'full_name': s.full_name,
                    'site_name': site.name if site else None,
                    'mobile': s.mobile,
                    'phone': s.phone,
                    'allow_emergency_clock': getattr(s, 'allow_emergency_clock', False) or False
                })

        # Get standby staff for today (sites with standby_staff_id set)
        standby_staff = []
        sites_with_standby = db.query(Site).filter(
            Site.standby_staff_id.isnot(None),
            Site.is_active == True
        ).all()
        for site in sites_with_standby:
            standby_person = db.query(StaffMember).get(site.standby_staff_id)
            if standby_person:
                standby_staff.append({
                    'staff_id': standby_person.id,
                    'staff_name': standby_person.full_name,
                    'site_id': site.id,
                    'site_name': site.name
                })

        return jsonify({
            'signed_in': signed_in,
            'completed': completed,
            'not_signed_in': not_signed_in,
            'not_working': not_working_staff,
            'standby_staff': standby_staff,
            'signed_in_count': len(signed_in),
            'signed_out_count': len(completed),
            'not_signed_in_count': len(not_signed_in),
            'not_working_count': len(not_working_staff),
            'total_hours': total_hours,
            'total_value': round(total_value, 2),
            'is_no_work_day': is_no_work_day
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/signin-on-behalf', methods=['POST'])
@token_required
@admin_required
def admin_signin_on_behalf(current_user):
    """Admin signs in a staff member on their behalf (for casuals without phones)"""
    db = SessionLocal()
    try:
        data = request.get_json()
        staff_id = data.get('staff_id')

        if not staff_id:
            return jsonify({'error': 'staff_id required'}), 400

        staff = db.query(StaffMember).filter(StaffMember.id == staff_id).first()
        if not staff:
            return jsonify({'error': 'Staff member not found'}), 404

        today = date.today()
        now = datetime.now()

        # Check if already signed in today
        existing = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == staff_id,
            WorkerAttendance.work_date == today,
            WorkerAttendance.signout_time.is_(None)  # Active session
        ).first()

        if existing:
            return jsonify({'error': f'{staff.full_name} is already signed in'}), 400

        # Create attendance record
        site = db.query(Site).get(staff.site_id) if staff.site_id else None

        attendance = WorkerAttendance(
            staff_id=staff_id,
            site_id=staff.site_id,
            work_date=today,
            signin_time=now,
            status=CheckInStatus.PENDING,
            gps_verified=False,  # No GPS for admin sign-in
            notes=f'Signed in by admin ({current_user.username}) on behalf'
        )
        db.add(attendance)
        db.commit()

        # Send admin notification SMS
        site_name = site.name if site else 'No Site'
        send_admin_sms(f"SIGNIN (admin): {staff.full_name} at {site_name} @ {now.strftime('%H:%M')} - by {current_user.username}", 'signin')

        return jsonify({
            'success': True,
            'message': f'{staff.full_name} signed in successfully',
            'attendance_id': attendance.id,
            'signin_time': now.strftime('%H:%M')
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/signout-on-behalf', methods=['POST'])
@token_required
@admin_required
def admin_signout_on_behalf(current_user):
    """Admin signs out a staff member on their behalf"""
    db = SessionLocal()
    try:
        data = request.get_json()
        staff_id = data.get('staff_id')

        if not staff_id:
            return jsonify({'error': 'staff_id required'}), 400

        staff = db.query(StaffMember).filter(StaffMember.id == staff_id).first()
        if not staff:
            return jsonify({'error': 'Staff member not found'}), 404

        today = date.today()
        now = datetime.now()

        # Find active attendance record
        attendance = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == staff_id,
            WorkerAttendance.work_date == today,
            WorkerAttendance.signout_time.is_(None)
        ).first()

        if not attendance:
            return jsonify({'error': f'{staff.full_name} is not signed in'}), 400

        # Sign out
        attendance.signout_time = now
        attendance.status = CheckInStatus.COMPLETED

        # Calculate hours worked
        if attendance.signin_time:
            hours = (now - attendance.signin_time).total_seconds() / 3600
            attendance.hours_worked = round(hours, 2)

        attendance.notes = (attendance.notes or '') + f' | Signed out by admin ({current_user.username})'
        db.commit()

        # Calculate net hours for display (after break deductions)
        gross_hours = attendance.hours_worked or 0
        BREAK_HOURS = 1.5  # 1hr lunch + 30min tea
        FULL_DAY_THRESHOLD = 9.0
        HALF_DAY_THRESHOLD = 4.5

        if gross_hours >= FULL_DAY_THRESHOLD:
            net_hours = gross_hours - BREAK_HOURS
        elif gross_hours >= HALF_DAY_THRESHOLD:
            net_hours = gross_hours - 0.5
        else:
            net_hours = gross_hours

        # Send admin notification SMS (use NET hours after break deductions)
        site = db.query(Site).get(staff.site_id) if staff.site_id else None
        site_name = site.name if site else 'No Site'
        send_admin_sms(f"SIGNOUT (admin): {staff.full_name} at {site_name} @ {now.strftime('%H:%M')} ({round(net_hours, 2)}hrs) - by {current_user.username}", 'signout')

        return jsonify({
            'success': True,
            'message': f'{staff.full_name} signed out successfully',
            'signout_time': now.strftime('%H:%M'),
            'hours_worked': round(net_hours, 2)
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# ===== ATTENDANCE REMINDERS API =====

@app.route('/api/reminders/today')
@token_required
def get_todays_reminders(current_user):
    """Get today's attendance reminders with status"""
    db = SessionLocal()
    try:
        today = date.today()

        # AUTO-SYNC: Update reminder statuses based on actual attendance
        # This fixes any reminders that are stuck as "Escalated" when staff have signed in
        reminders = db.query(AttendanceReminder).filter(
            AttendanceReminder.work_date == today
        ).all()

        synced_count = 0
        for r in reminders:
            if r.status != ReminderStatus.RESPONDED:
                # Check if staff has actually signed in/out
                attendance = db.query(WorkerAttendance).filter(
                    WorkerAttendance.staff_id == r.staff_id,
                    WorkerAttendance.work_date == today
                ).first()

                if r.reminder_type == ReminderType.CLOCKIN:
                    if attendance and attendance.signin_time:
                        # Staff has signed in - update reminder to responded
                        r.status = ReminderStatus.RESPONDED
                        r.responded_at = attendance.signin_time
                        r.attendance_id = attendance.id
                        synced_count += 1
                elif r.reminder_type == ReminderType.CLOCKOUT:
                    if attendance and attendance.signout_time:
                        # Staff has signed out - update reminder to responded
                        r.status = ReminderStatus.RESPONDED
                        r.responded_at = attendance.signout_time
                        r.attendance_id = attendance.id
                        synced_count += 1

        if synced_count > 0:
            db.commit()
            print(f"[REMINDER SYNC] Auto-updated {synced_count} reminder statuses")

        # Get all staff on leave today
        leave_records = db.query(LeaveRecord).filter(
            LeaveRecord.leave_date == today,
            LeaveRecord.status != LeaveStatus.CANCELLED
        ).all()
        staff_leave_map = {lr.staff_id: lr.leave_type.value for lr in leave_records}

        result = []
        for r in reminders:
            staff = db.query(StaffMember).get(r.staff_id)
            site = db.query(Site).get(r.site_id) if r.site_id else None

            # Check if staff is on leave
            leave_type = staff_leave_map.get(r.staff_id)

            result.append({
                'id': r.id,
                'staff_id': r.staff_id,
                'staff_name': staff.full_name if staff else 'Unknown',
                'mobile': staff.mobile if staff else None,
                'site_name': site.name if site else 'No Site',
                'reminder_type': r.reminder_type.value,
                'status': r.status.value,
                'first_sms_sent_at': r.first_sms_sent_at.isoformat() if r.first_sms_sent_at else None,
                'second_sms_sent_at': r.second_sms_sent_at.isoformat() if r.second_sms_sent_at else None,
                'responded_at': r.responded_at.isoformat() if r.responded_at else None,
                'late_minutes': r.late_minutes,
                'early_departure_minutes': r.early_departure_minutes,
                'notes': r.notes,
                'on_leave': leave_type is not None,
                'leave_type': leave_type
            })

        return jsonify(result)

    finally:
        db.close()


@app.route('/api/reminders/summary')
@token_required
def get_reminder_summary(current_user):
    """Get summary of today's attendance reminders"""
    db = SessionLocal()
    try:
        today = date.today()

        # Get staff count
        active_staff = db.query(StaffMember).filter(
            StaffMember.is_active == True,
            StaffMember.mobile != None,
            StaffMember.mobile != ''
        ).count()

        # Get today's attendance
        clocked_in = db.query(WorkerAttendance).filter(
            WorkerAttendance.work_date == today,
            WorkerAttendance.signin_time != None
        ).count()

        clocked_out = db.query(WorkerAttendance).filter(
            WorkerAttendance.work_date == today,
            WorkerAttendance.signout_time != None
        ).count()

        # Get reminder stats
        clockin_reminders = db.query(AttendanceReminder).filter(
            AttendanceReminder.work_date == today,
            AttendanceReminder.reminder_type == ReminderType.CLOCKIN
        ).count()

        clockin_responded = db.query(AttendanceReminder).filter(
            AttendanceReminder.work_date == today,
            AttendanceReminder.reminder_type == ReminderType.CLOCKIN,
            AttendanceReminder.status == ReminderStatus.RESPONDED
        ).count()

        clockin_no_response = db.query(AttendanceReminder).filter(
            AttendanceReminder.work_date == today,
            AttendanceReminder.reminder_type == ReminderType.CLOCKIN,
            AttendanceReminder.status == ReminderStatus.NO_RESPONSE
        ).count()

        clockin_not_working = db.query(AttendanceReminder).filter(
            AttendanceReminder.work_date == today,
            AttendanceReminder.reminder_type == ReminderType.CLOCKIN,
            AttendanceReminder.status == ReminderStatus.NOT_WORKING
        ).count()

        late_workers = db.query(AttendanceReminder).filter(
            AttendanceReminder.work_date == today,
            AttendanceReminder.late_minutes > 0
        ).count()

        return jsonify({
            'date': today.isoformat(),
            'active_staff': active_staff,
            'clocked_in': clocked_in,
            'clocked_out': clocked_out,
            'not_clocked_in': active_staff - clocked_in,
            'clockin_reminders_sent': clockin_reminders,
            'clockin_responded': clockin_responded,
            'clockin_no_response': clockin_no_response,
            'clockin_not_working': clockin_not_working,
            'late_workers': late_workers
        })

    finally:
        db.close()


@app.route('/api/reminders/send-manual', methods=['POST'])
@token_required
@admin_required
def send_manual_reminder(current_user):
    """Manually send a reminder SMS to a specific staff member"""
    db = SessionLocal()
    try:
        data = request.json
        staff_id = data.get('staff_id')
        reminder_type = data.get('reminder_type', 'clockin')

        staff = db.query(StaffMember).get(staff_id)
        if not staff:
            return jsonify({'error': 'Staff member not found'}), 404

        if not staff.mobile and not staff.phone:
            return jsonify({'error': 'Staff member has no mobile number'}), 400

        # Check attendance status before sending
        today = date.today()

        # Check if staff is on leave today
        leave = db.query(LeaveRecord).filter(
            LeaveRecord.staff_id == staff_id,
            LeaveRecord.leave_date == today,
            LeaveRecord.status != LeaveStatus.CANCELLED
        ).first()
        if leave:
            leave_type = 'Booked Leave' if leave.leave_type == LeaveType.BOOKED else 'Sick Leave'
            return jsonify({
                'error': f'{staff.first_name} is on {leave_type} today'
            }), 400

        attendance = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == staff_id,
            WorkerAttendance.work_date == today
        ).first()

        if reminder_type == 'clockin':
            # Don't send clock-in reminder if already clocked in
            if attendance and attendance.signin_time:
                return jsonify({
                    'error': f'{staff.first_name} has already clocked in at {attendance.signin_time.strftime("%H:%M")}'
                }), 400
        else:
            # Don't send clock-out reminder if already clocked out
            if attendance and attendance.signout_time:
                return jsonify({
                    'error': f'{staff.first_name} has already clocked out at {attendance.signout_time.strftime("%H:%M")}'
                }), 400
            # Don't send clock-out reminder if not clocked in
            if not attendance or not attendance.signin_time:
                return jsonify({
                    'error': f'{staff.first_name} has not clocked in today'
                }), 400

        mobile = staff.mobile or staff.phone
        mobile_param = mobile.replace(' ', '') if mobile else ''
        clockin_link = f"{PUBLIC_URL}/clockin?m={mobile_param}"

        if reminder_type == 'clockin':
            message = f"WAGEPRO: {staff.first_name}, please clock in now: {clockin_link}"
            rem_type = ReminderType.CLOCKIN
        else:
            message = f"WAGEPRO: {staff.first_name}, please clock out now: {clockin_link}"
            rem_type = ReminderType.CLOCKOUT

        # Check if reminder already exists for this staff/date/type
        existing_reminder = db.query(AttendanceReminder).filter(
            AttendanceReminder.staff_id == staff_id,
            AttendanceReminder.work_date == date.today(),
            AttendanceReminder.reminder_type == rem_type
        ).first()

        if existing_reminder:
            # Update existing reminder
            if not existing_reminder.first_sms_sent_at:
                existing_reminder.first_sms_sent_at = datetime.now()
                existing_reminder.first_sms_status = 'sent'
                existing_reminder.status = ReminderStatus.SENT
            else:
                # Already has first SMS, this is escalation
                existing_reminder.second_sms_sent_at = datetime.now()
                existing_reminder.second_sms_status = 'sent'
                existing_reminder.status = ReminderStatus.ESCALATED
            existing_reminder.notes = (existing_reminder.notes or '') + f' | Manual by {current_user.username}'
            reminder = existing_reminder
        else:
            # Create new reminder record
            reminder = AttendanceReminder(
                staff_id=staff_id,
                site_id=staff.site_id,
                work_date=date.today(),
                reminder_type=rem_type,
                scheduled_time=datetime.now(),
                first_sms_sent_at=datetime.now(),
                first_sms_status='sent',
                status=ReminderStatus.SENT,
                notes=f'Manual reminder by {current_user.username}'
            )
            db.add(reminder)
        db.commit()

        # Send SMS
        notifier = SMSNotifier()
        messages = [{'mobile': mobile, 'message': message}]
        batch_file = notifier.create_batch_file(messages)
        if batch_file:
            success, status = notifier.upload_to_winsms(batch_file)

            # Log SMS to database
            if success:
                import os
                sms_type = SMSType.CLOCKIN_REMINDER if reminder_type == 'clockin' else SMSType.CLOCKOUT_REMINDER
                log_sms(
                    db=db,
                    staff_id=staff_id,
                    phone_number=mobile,
                    message=message,
                    sms_type=sms_type,
                    batch_filename=os.path.basename(batch_file),
                    sent_by_id=current_user.id
                )
                db.commit()

            return jsonify({
                'success': success,
                'message': f'Reminder sent to {staff.full_name}',
                'sms_status': status
            })

        return jsonify({'error': 'Failed to create SMS batch'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/reminders/resend/<int:reminder_id>', methods=['POST'])
@token_required
@admin_required
def resend_reminder(current_user, reminder_id):
    """Resend a failed or pending reminder SMS"""
    db = SessionLocal()
    try:
        reminder = db.query(AttendanceReminder).get(reminder_id)
        if not reminder:
            return jsonify({'error': 'Reminder not found'}), 404

        staff = db.query(StaffMember).get(reminder.staff_id)
        if not staff:
            return jsonify({'error': 'Staff member not found'}), 404

        mobile = staff.mobile or staff.phone
        if not mobile:
            return jsonify({'error': 'Staff member has no mobile number'}), 400

        clockin_link = f"{PUBLIC_URL}/clockin"

        if reminder.reminder_type == ReminderType.CLOCKIN:
            message = f"WAGEPRO: {staff.first_name}, please clock in now: {clockin_link}"
        else:
            message = f"WAGEPRO: {staff.first_name}, please clock out now: {clockin_link}"

        # Send SMS
        notifier = SMSNotifier()
        messages = [{'mobile': mobile, 'message': message}]
        batch_file = notifier.create_batch_file(messages)
        if batch_file:
            success, status = notifier.upload_to_winsms(batch_file)
            if success:
                # Update reminder record - set escalation time to track last send
                reminder.second_sms_sent_at = datetime.now()
                reminder.second_sms_status = 'resent'
                reminder.status = ReminderStatus.ESCALATED
                reminder.notes = (reminder.notes or '') + f' | Resent by {current_user.username} at {datetime.now().strftime("%H:%M")}'
                db.commit()

                return jsonify({
                    'success': True,
                    'message': f'Reminder resent to {staff.full_name}',
                    'sms_status': status
                })
            else:
                return jsonify({'error': f'SMS upload failed: {status}'}), 500

        return jsonify({'error': 'Failed to create SMS batch'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/sms/bulk', methods=['POST'])
@token_required
@admin_required
def send_bulk_sms(current_user):
    """Send a general SMS to all staff at a site or company-wide"""
    db = SessionLocal()
    try:
        data = request.json
        site_id = data.get('site_id')
        message = data.get('message', '').strip()

        if not message:
            return jsonify({'error': 'Message is required'}), 400

        # Get staff members with mobile numbers
        query = db.query(StaffMember).filter(
            StaffMember.is_active == True,
            or_(
                StaffMember.mobile.isnot(None),
                StaffMember.phone.isnot(None)
            )
        )

        if site_id:
            query = query.filter(StaffMember.site_id == site_id)

        staff_list = query.all()

        if not staff_list:
            return jsonify({'error': 'No staff members found with mobile numbers'}), 400

        # Build message list with staff info for logging
        messages = []
        staff_info = []  # Store staff info for logging
        for staff in staff_list:
            mobile = staff.mobile or staff.phone
            if mobile:
                # Prefix message with WAGEPRO
                full_message = f"WAGEPRO: {message}"
                messages.append({'mobile': mobile, 'message': full_message})
                staff_info.append({'id': staff.id, 'mobile': mobile, 'message': full_message})

        # Send SMS
        notifier = SMSNotifier()
        batch_file = notifier.create_batch_file(messages)
        if batch_file:
            success, status = notifier.upload_to_winsms(batch_file)
            if success:
                site_name = "All Sites"
                if site_id:
                    site = db.query(Site).get(site_id)
                    site_name = site.name if site else "Unknown Site"

                print(f"[BULK SMS] Sent to {len(messages)} staff at {site_name} by {current_user.username}: {message[:50]}...")

                # Log each SMS to the database
                import os
                batch_filename = os.path.basename(batch_file) if batch_file else None
                for info in staff_info:
                    log_sms(
                        db=db,
                        staff_id=info['id'],
                        phone_number=info['mobile'],
                        message=info['message'],
                        sms_type=SMSType.BULK_MESSAGE,
                        batch_filename=batch_filename,
                        sent_by_id=current_user.id
                    )
                db.commit()

                return jsonify({
                    'success': True,
                    'sent_count': len(messages),
                    'site': site_name,
                    'sms_status': status
                })
            else:
                return jsonify({'error': f'SMS upload failed: {status}'}), 500

        return jsonify({'error': 'Failed to create SMS batch'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/reminders/late-report')
@token_required
def get_late_report(current_user):
    """Get report of late clock-ins for date range"""
    db = SessionLocal()
    try:
        # Default to current month
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')

        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        else:
            start_date = date.today().replace(day=1)

        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        else:
            end_date = date.today()

        # Get late reminders
        late_records = db.query(AttendanceReminder).filter(
            AttendanceReminder.work_date >= start_date,
            AttendanceReminder.work_date <= end_date,
            AttendanceReminder.late_minutes > 0
        ).order_by(AttendanceReminder.work_date.desc()).all()

        result = []
        for r in late_records:
            staff = db.query(StaffMember).get(r.staff_id)
            result.append({
                'date': r.work_date.isoformat(),
                'staff_id': r.staff_id,
                'staff_name': staff.full_name if staff else 'Unknown',
                'late_minutes': r.late_minutes,
                'status': r.status.value
            })

        # Group by staff for summary
        staff_summary = {}
        for r in result:
            if r['staff_name'] not in staff_summary:
                staff_summary[r['staff_name']] = {'count': 0, 'total_minutes': 0}
            staff_summary[r['staff_name']]['count'] += 1
            staff_summary[r['staff_name']]['total_minutes'] += r['late_minutes']

        return jsonify({
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat(),
            'records': result,
            'summary': staff_summary
        })

    finally:
        db.close()


# ===== LEAVE API =====

@app.route('/api/leave')
@token_required
def get_leave_records(current_user):
    """Get leave records with optional filters"""
    db = SessionLocal()
    try:
        query = db.query(LeaveRecord)

        # Filter by staff_id
        staff_id = request.args.get('staff_id')
        if staff_id:
            query = query.filter(LeaveRecord.staff_id == int(staff_id))

        # Filter by date range
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        if start_date:
            query = query.filter(LeaveRecord.leave_date >= date.fromisoformat(start_date))
        if end_date:
            query = query.filter(LeaveRecord.leave_date <= date.fromisoformat(end_date))

        # Filter by leave type
        leave_type = request.args.get('leave_type')
        if leave_type:
            query = query.filter(LeaveRecord.leave_type == LeaveType(leave_type))

        # Filter by status
        status = request.args.get('status')
        if status:
            query = query.filter(LeaveRecord.status == LeaveStatus(status))

        # Order by date descending
        records = query.order_by(LeaveRecord.leave_date.desc()).all()

        return jsonify([{
            'id': r.id,
            'staff_id': r.staff_id,
            'staff_name': r.staff.full_name if r.staff else None,
            'site_id': r.site_id,
            'site_name': r.site.name if r.site else None,
            'leave_date': r.leave_date.isoformat(),
            'leave_type': r.leave_type.value,
            'status': r.status.value,
            'reason': r.reason,
            'notes': r.notes,
            'entered_by': r.entered_by.username if r.entered_by else None,
            'entered_at': r.entered_at.isoformat() if r.entered_at else None
        } for r in records])

    finally:
        db.close()


@app.route('/api/leave', methods=['POST'])
@token_required
def create_leave_record(current_user):
    """Create a new leave record (book leave)"""
    db = SessionLocal()
    try:
        data = request.json
        staff_id = data.get('staff_id')
        leave_dates = data.get('leave_dates', [])  # Can be single date or array
        leave_type = data.get('leave_type', 'L')  # L or S
        reason = data.get('reason', '')

        if not staff_id:
            return jsonify({'error': 'staff_id is required'}), 400
        if not leave_dates:
            return jsonify({'error': 'leave_dates is required'}), 400

        # Handle single date or array
        if isinstance(leave_dates, str):
            leave_dates = [leave_dates]

        staff = db.query(StaffMember).filter(StaffMember.id == staff_id).first()
        if not staff:
            return jsonify({'error': 'Staff not found'}), 404

        created = []
        skipped = []
        skipped_holidays = []
        skipped_weekends = []

        for leave_date_str in leave_dates:
            leave_date = date.fromisoformat(leave_date_str)

            # Skip weekends (Saturday=5, Sunday=6)
            if leave_date.weekday() >= 5:
                skipped_weekends.append(leave_date_str)
                continue

            # Skip public holidays
            if is_public_holiday(leave_date):
                holiday_name = get_holiday_name(leave_date)
                skipped_holidays.append({'date': leave_date_str, 'holiday': holiday_name})
                continue

            # Check if leave already exists for this date
            existing = db.query(LeaveRecord).filter(
                LeaveRecord.staff_id == staff_id,
                LeaveRecord.leave_date == leave_date,
                LeaveRecord.status != LeaveStatus.CANCELLED
            ).first()

            if existing:
                skipped.append(leave_date_str)
                continue

            record = LeaveRecord(
                staff_id=staff_id,
                site_id=staff.site_id,
                leave_date=leave_date,
                leave_type=LeaveType(leave_type),
                status=LeaveStatus.APPROVED,  # Auto-approve for now
                reason=reason,
                entered_by_id=current_user.id,
                entered_at=datetime.now(),
                approved_by_id=current_user.id,
                approved_at=datetime.now()
            )
            db.add(record)
            created.append(leave_date_str)

        db.commit()

        # Build message with details
        msg_parts = [f'Created {len(created)} leave record(s)']
        if skipped_weekends:
            msg_parts.append(f'Skipped {len(skipped_weekends)} weekend(s)')
        if skipped_holidays:
            msg_parts.append(f'Skipped {len(skipped_holidays)} public holiday(s)')
        if skipped:
            msg_parts.append(f'Skipped {len(skipped)} existing leave(s)')

        return jsonify({
            'success': True,
            'message': '. '.join(msg_parts),
            'created': created,
            'skipped': skipped,
            'skipped_weekends': skipped_weekends,
            'skipped_holidays': skipped_holidays
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/leave/<int:leave_id>', methods=['DELETE'])
@token_required
def delete_leave_record(current_user, leave_id):
    """Cancel/delete a leave record"""
    db = SessionLocal()
    try:
        record = db.query(LeaveRecord).filter(LeaveRecord.id == leave_id).first()
        if not record:
            return jsonify({'error': 'Leave record not found'}), 404

        # Mark as cancelled instead of deleting
        record.status = LeaveStatus.CANCELLED
        record.notes = (record.notes or '') + f' | Cancelled by {current_user.username} at {datetime.now().strftime("%Y-%m-%d %H:%M")}'
        db.commit()

        return jsonify({'success': True, 'message': 'Leave record cancelled'})

    finally:
        db.close()


@app.route('/api/leave/check/<int:staff_id>/<leave_date>')
@token_required
def check_leave(current_user, staff_id, leave_date):
    """Check if staff has leave on a specific date"""
    db = SessionLocal()
    try:
        record = db.query(LeaveRecord).filter(
            LeaveRecord.staff_id == staff_id,
            LeaveRecord.leave_date == date.fromisoformat(leave_date),
            LeaveRecord.status == LeaveStatus.APPROVED
        ).first()

        if record:
            return jsonify({
                'has_leave': True,
                'leave_type': record.leave_type.value,
                'reason': record.reason
            })
        else:
            return jsonify({'has_leave': False})

    finally:
        db.close()


@app.route('/api/leave/today')
@token_required
def get_todays_leave(current_user):
    """Get all staff on leave today"""
    db = SessionLocal()
    try:
        today = date.today()
        records = db.query(LeaveRecord).filter(
            LeaveRecord.leave_date == today,
            LeaveRecord.status == LeaveStatus.APPROVED
        ).all()

        return jsonify([{
            'id': r.id,
            'staff_id': r.staff_id,
            'staff_name': r.staff.full_name if r.staff else None,
            'site_name': r.site.name if r.site else None,
            'leave_type': r.leave_type.value,
            'reason': r.reason
        } for r in records])

    finally:
        db.close()


@app.route('/api/leave/upcoming')
@token_required
def get_upcoming_leave(current_user):
    """Get upcoming booked leave (next 30 days)"""
    db = SessionLocal()
    try:
        today = date.today()
        end_date = today + timedelta(days=30)

        records = db.query(LeaveRecord).filter(
            LeaveRecord.leave_date >= today,
            LeaveRecord.leave_date <= end_date,
            LeaveRecord.status == LeaveStatus.APPROVED
        ).order_by(LeaveRecord.leave_date).all()

        return jsonify([{
            'id': r.id,
            'staff_id': r.staff_id,
            'staff_name': r.staff.full_name if r.staff else None,
            'site_name': r.site.name if r.site else None,
            'leave_date': r.leave_date.isoformat(),
            'leave_type': r.leave_type.value,
            'reason': r.reason
        } for r in records])

    finally:
        db.close()


@app.route('/api/leave/stats')
@token_required
def get_leave_stats(current_user):
    """Get leave statistics"""
    db = SessionLocal()
    try:
        # Get date range from params or default to current year
        year = int(request.args.get('year', date.today().year))
        start_date = date(year, 1, 1)
        end_date = date(year, 12, 31)

        staff_id = request.args.get('staff_id')

        query = db.query(LeaveRecord).filter(
            LeaveRecord.leave_date >= start_date,
            LeaveRecord.leave_date <= end_date,
            LeaveRecord.status == LeaveStatus.APPROVED
        )

        if staff_id:
            query = query.filter(LeaveRecord.staff_id == int(staff_id))

        records = query.all()

        # Calculate stats
        total_leave = len(records)
        booked_leave = len([r for r in records if r.leave_type == LeaveType.BOOKED])
        sick_leave = len([r for r in records if r.leave_type == LeaveType.SICK])

        # Group by staff
        by_staff = {}
        for r in records:
            staff_name = r.staff.full_name if r.staff else 'Unknown'
            if staff_name not in by_staff:
                by_staff[staff_name] = {'L': 0, 'S': 0, 'total': 0}
            by_staff[staff_name][r.leave_type.value] += 1
            by_staff[staff_name]['total'] += 1

        # Group by month
        by_month = {}
        for r in records:
            month_key = r.leave_date.strftime('%Y-%m')
            if month_key not in by_month:
                by_month[month_key] = {'L': 0, 'S': 0, 'total': 0}
            by_month[month_key][r.leave_type.value] += 1
            by_month[month_key]['total'] += 1

        return jsonify({
            'year': year,
            'total_leave_days': total_leave,
            'booked_leave_days': booked_leave,
            'sick_leave_days': sick_leave,
            'by_staff': by_staff,
            'by_month': by_month
        })

    finally:
        db.close()


# ===== CONFIG API =====

# Note: system_config is defined above in WHEREABOUTS section


@app.route('/api/config')
@token_required
def get_config(current_user):
    """Get system configuration"""
    return jsonify(system_config)


@app.route('/api/config', methods=['POST'])
@token_required
def save_config(current_user):
    """Save system configuration"""
    global system_config, ADMIN_MOBILE

    try:
        data = request.json

        system_config['admin_name'] = data.get('admin_name', system_config['admin_name'])
        system_config['admin_email'] = data.get('admin_email', system_config['admin_email'])
        system_config['admin_mobile'] = data.get('admin_mobile', system_config['admin_mobile'])
        system_config['company_name'] = data.get('company_name', system_config['company_name'])
        system_config['notify_signin'] = data.get('notify_signin', True)
        system_config['notify_signout'] = data.get('notify_signout', True)
        system_config['notify_location'] = data.get('notify_location', True)

        # Attendance reminder settings
        system_config['reminder_enabled'] = data.get('reminder_enabled', system_config.get('reminder_enabled', True))
        system_config['clockin_time'] = data.get('clockin_time', system_config.get('clockin_time', '07:20'))
        system_config['clockin_grace_minutes'] = data.get('clockin_grace_minutes', system_config.get('clockin_grace_minutes', 10))
        system_config['clockout_time'] = data.get('clockout_time', system_config.get('clockout_time', '16:30'))
        system_config['clockout_window_minutes'] = data.get('clockout_window_minutes', system_config.get('clockout_window_minutes', 10))
        system_config['notify_late_clockin'] = data.get('notify_late_clockin', system_config.get('notify_late_clockin', True))
        system_config['notify_missed_clockout'] = data.get('notify_missed_clockout', system_config.get('notify_missed_clockout', True))

        # Time window restrictions
        system_config['enforce_clockin_window'] = data.get('enforce_clockin_window', system_config.get('enforce_clockin_window', True))
        system_config['clockin_window_start'] = data.get('clockin_window_start', system_config.get('clockin_window_start', '07:00'))
        system_config['clockin_window_end'] = data.get('clockin_window_end', system_config.get('clockin_window_end', '07:45'))
        system_config['enforce_clockout_window'] = data.get('enforce_clockout_window', system_config.get('enforce_clockout_window', True))
        system_config['clockout_window_start'] = data.get('clockout_window_start', system_config.get('clockout_window_start', '16:15'))
        system_config['clockout_window_end'] = data.get('clockout_window_end', system_config.get('clockout_window_end', '16:45'))

        # Update the global ADMIN_MOBILE
        ADMIN_MOBILE = system_config['admin_mobile']

        return jsonify({'success': True, 'message': 'Configuration saved'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/clockin/config')
def get_clockin_config():
    """Get clock-in/out times for worker app (no auth required)"""
    return jsonify({
        'clockin_time': system_config.get('clockin_time', '07:20'),
        'clockin_window_start': system_config.get('clockin_window_start', '07:00'),
        'clockin_window_end': system_config.get('clockin_window_end', '09:00'),
        'clockout_time': system_config.get('clockout_time', '16:30'),
        'clockout_window_start': system_config.get('clockout_window_start', '16:15'),
        'clockout_window_end': system_config.get('clockout_window_end', '16:45')
    })


@app.route('/api/config/public-url', methods=['POST'])
@token_required
def save_public_url(current_user):
    """Save public URL for location links"""
    global PUBLIC_URL, system_config

    try:
        data = request.json
        new_url = data.get('public_url', '')

        if new_url:
            PUBLIC_URL = new_url
            system_config['public_url'] = new_url

        return jsonify({'success': True, 'message': 'Public URL saved', 'public_url': PUBLIC_URL})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ===== KIOSK MODE - FACE RECOGNITION =====

@app.route('/kiosk')
def kiosk_page():
    """Serve kiosk face recognition clock-in page"""
    return send_from_directory('templates', 'kiosk.html')


@app.route('/face-enroll')
def face_enroll_page():
    """Serve face enrollment admin page"""
    return send_from_directory('templates', 'face_enroll.html')


@app.route('/api/kiosk/staff-faces', methods=['GET'])
def get_staff_faces():
    """Get all enrolled staff face descriptors for client-side matching"""
    db = SessionLocal()
    try:
        import json

        # Get all active staff with face descriptors
        staff_list = db.query(StaffMember).filter(
            StaffMember.is_active == True,
            StaffMember.face_descriptor.isnot(None)
        ).all()

        result = []
        for staff in staff_list:
            try:
                descriptor = json.loads(staff.face_descriptor)
                site_name = staff.site.name if staff.site else None
                result.append({
                    'id': staff.id,
                    'name': staff.full_name,
                    'site': site_name,
                    'descriptor': descriptor
                })
            except (json.JSONDecodeError, TypeError):
                continue

        return jsonify({
            'success': True,
            'staff': result,
            'count': len(result)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/kiosk/clockin', methods=['POST'])
def kiosk_clockin():
    """Clock in via kiosk face recognition"""
    db = SessionLocal()
    try:
        data = request.json
        staff_id = data.get('staff_id')
        confidence = data.get('confidence', 0)

        if not staff_id:
            return jsonify({'error': 'Staff ID required'}), 400

        staff = db.query(StaffMember).get(staff_id)
        if not staff:
            return jsonify({'error': 'Staff not found'}), 404

        today = date.today()
        now = datetime.now()

        # AUTO-CLEANUP: Close any orphan records from previous days
        # Rules: ALL missing sign-outs get backdated to 16:30 with 20 penalty points
        # If overtime was declared, cancel it too
        orphan_records = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == staff_id,
            WorkerAttendance.work_date < today,
            WorkerAttendance.signout_time.is_(None)
        ).all()

        for orphan in orphan_records:
            if orphan.signin_time:
                has_overtime = orphan.overtime_minutes and orphan.overtime_minutes > 0

                orphan.signout_time = datetime.combine(orphan.work_date, datetime.strptime('16:30', '%H:%M').time())

                if has_overtime:
                    orphan.overtime_minutes = 0
                    orphan.overtime_reason = None
                    orphan.overtime_confirmed = False
                    orphan.notes = (orphan.notes or '') + ' [AUTO-CLOSED: Overtime CANCELLED - no sign-out - 20 penalty points]'
                else:
                    orphan.notes = (orphan.notes or '') + ' [AUTO-CLOSED: Missing sign-out - 20 penalty points]'

                # Get current pay period for penalty
                current_period = db.query(PayPeriod).filter(
                    PayPeriod.status == PayPeriodStatus.OPEN
                ).order_by(PayPeriod.start_date.desc()).first()

                if current_period:
                    penalty = StaffRewardPenalty(
                        staff_id=staff_id,
                        pay_period_id=current_period.id,
                        points=-20,
                        category=RewardPenaltyCategory.EARLY_DEPARTURE,
                        source=RewardPenaltySource.SYSTEM,
                        status=RewardPenaltyStatus.APPROVED,
                        description=f'Missing sign-out on {orphan.work_date.strftime("%Y-%m-%d")} - auto-closed',
                        created_by_id=None,
                        approved_by_id=None,
                        approved_at=datetime.now()
                    )
                    db.add(penalty)

                orphan.hours_worked = round((orphan.signout_time - orphan.signin_time).total_seconds() / 3600, 2)
                orphan.status = CheckInStatus.COMPLETED
            else:
                db.delete(orphan)

        if orphan_records:
            db.commit()

        # Check if already signed in today (and not signed out)
        existing = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == staff_id,
            WorkerAttendance.work_date == today,
            WorkerAttendance.signout_time.is_(None)
        ).first()

        if existing:
            return jsonify({
                'error': f'Already signed in at {existing.signin_time.strftime("%H:%M")}',
                'success': False
            }), 400

        # Create attendance record (kiosk mode - no GPS)
        attendance = WorkerAttendance(
            staff_id=staff_id,
            site_id=staff.site_id,
            work_date=today,
            signin_time=now,
            status=CheckInStatus.PENDING,
            notes=f'Kiosk face recognition (confidence: {confidence}%)'
        )

        db.add(attendance)
        db.commit()

        # Send admin notification if enabled
        if system_config.get('notify_signin', True):
            site_name = staff.site.name if staff.site else 'Unknown Site'
            msg = f"KIOSK SIGNIN: {staff.full_name} at {site_name} @ {now.strftime('%H:%M')}"
            send_admin_sms(msg, 'signin')

        return jsonify({
            'success': True,
            'message': f'Signed in at {now.strftime("%H:%M")}',
            'staff_name': staff.full_name
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/kiosk/clockout', methods=['POST'])
def kiosk_clockout():
    """Clock out via kiosk face recognition"""
    db = SessionLocal()
    try:
        data = request.json
        staff_id = data.get('staff_id')
        confidence = data.get('confidence', 0)

        if not staff_id:
            return jsonify({'error': 'Staff ID required'}), 400

        staff = db.query(StaffMember).get(staff_id)
        if not staff:
            return jsonify({'error': 'Staff not found'}), 404

        today = date.today()
        now = datetime.now()

        # Find open attendance record
        attendance = db.query(WorkerAttendance).filter(
            WorkerAttendance.staff_id == staff_id,
            WorkerAttendance.work_date == today,
            WorkerAttendance.signout_time.is_(None)
        ).first()

        if not attendance:
            return jsonify({
                'error': 'No active sign-in found. Please sign in first.',
                'success': False
            }), 400

        # Update attendance
        attendance.signout_time = now
        attendance.status = CheckInStatus.COMPLETED

        # Calculate hours worked
        if attendance.signin_time:
            delta = now - attendance.signin_time
            hours_worked = round(delta.total_seconds() / 3600, 2)
            attendance.hours_worked = hours_worked

            # Add note
            if attendance.notes:
                attendance.notes += f' | Out: {confidence}%'
            else:
                attendance.notes = f'Kiosk out (confidence: {confidence}%)'

        db.commit()

        # Calculate net hours for display (after break deductions)
        gross_hours = hours_worked
        BREAK_HOURS = 1.5  # 1hr lunch + 30min tea
        FULL_DAY_THRESHOLD = 9.0
        HALF_DAY_THRESHOLD = 4.5

        if gross_hours >= FULL_DAY_THRESHOLD:
            net_hours = gross_hours - BREAK_HOURS
        elif gross_hours >= HALF_DAY_THRESHOLD:
            net_hours = gross_hours - 0.5
        else:
            net_hours = gross_hours

        # Send admin notification if enabled (use NET hours after break deductions)
        if system_config.get('notify_signout', True):
            site_name = staff.site.name if staff.site else 'Unknown Site'
            msg = f"KIOSK SIGNOUT: {staff.full_name} at {site_name} @ {now.strftime('%H:%M')} ({round(net_hours, 2)}hrs)"
            send_admin_sms(msg, 'signout')

        return jsonify({
            'success': True,
            'message': f'Signed out at {now.strftime("%H:%M")}',
            'hours_worked': round(net_hours, 2),  # Net hours for display (after break deductions)
            'staff_name': staff.full_name
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/kiosk/enroll', methods=['POST'])
@token_required
def enroll_face(current_user):
    """Enroll a staff member's face descriptor (admin only)"""
    if current_user.role != UserRole.ADMIN:
        return jsonify({'error': 'Admin access required'}), 403

    db = SessionLocal()
    try:
        import json

        data = request.json
        staff_id = data.get('staff_id')
        descriptor = data.get('descriptor')  # 128-dimension array from face-api.js

        if not staff_id or not descriptor:
            return jsonify({'error': 'Staff ID and face descriptor required'}), 400

        if not isinstance(descriptor, list) or len(descriptor) != 128:
            return jsonify({'error': 'Invalid face descriptor (must be 128-dimension array)'}), 400

        staff = db.query(StaffMember).get(staff_id)
        if not staff:
            return jsonify({'error': 'Staff not found'}), 404

        # Store descriptor as JSON
        staff.face_descriptor = json.dumps(descriptor)
        staff.face_enrolled_at = datetime.now()

        db.commit()

        return jsonify({
            'success': True,
            'message': f'Face enrolled for {staff.full_name}',
            'enrolled_at': staff.face_enrolled_at.isoformat()
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/kiosk/unenroll/<int:staff_id>', methods=['DELETE'])
@token_required
def unenroll_face(current_user, staff_id):
    """Remove a staff member's face enrollment (admin only)"""
    if current_user.role != UserRole.ADMIN:
        return jsonify({'error': 'Admin access required'}), 403

    db = SessionLocal()
    try:
        staff = db.query(StaffMember).get(staff_id)
        if not staff:
            return jsonify({'error': 'Staff not found'}), 404

        staff.face_descriptor = None
        staff.face_enrolled_at = None

        db.commit()

        return jsonify({
            'success': True,
            'message': f'Face unenrolled for {staff.full_name}'
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/kiosk/enrollment-status', methods=['GET'])
@token_required
def get_enrollment_status(current_user):
    """Get face enrollment status for all staff (admin only)"""
    if current_user.role != UserRole.ADMIN:
        return jsonify({'error': 'Admin access required'}), 403

    db = SessionLocal()
    try:
        staff_list = db.query(StaffMember).filter(
            StaffMember.is_active == True
        ).order_by(StaffMember.first_name).all()

        result = []
        for staff in staff_list:
            result.append({
                'id': staff.id,
                'name': staff.full_name,
                'site': staff.site.name if staff.site else None,
                'enrolled': staff.face_descriptor is not None,
                'enrolled_at': staff.face_enrolled_at.isoformat() if staff.face_enrolled_at else None
            })

        enrolled_count = sum(1 for s in result if s['enrolled'])

        return jsonify({
            'success': True,
            'staff': result,
            'total': len(result),
            'enrolled': enrolled_count,
            'not_enrolled': len(result) - enrolled_count
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()



# ===== EMERGENCY CLOCK-IN & STANDBY MANAGEMENT =====

@app.route('/api/admin/staff/<int:staff_id>/emergency-clock', methods=['POST'])
@token_required
@admin_required
def toggle_emergency_clock(current_user, staff_id):
    """Toggle emergency clock-in permission for a staff member"""
    db = SessionLocal()
    try:
        staff = db.query(StaffMember).get(staff_id)
        if not staff:
            return jsonify({'error': 'Staff member not found'}), 404

        data = request.json or {}
        allow = data.get('allow')

        # Toggle or set explicitly
        if allow is not None:
            staff.allow_emergency_clock = bool(allow)
        else:
            staff.allow_emergency_clock = not getattr(staff, 'allow_emergency_clock', False)

        db.commit()

        return jsonify({
            'success': True,
            'staff_id': staff_id,
            'staff_name': staff.full_name,
            'allow_emergency_clock': staff.allow_emergency_clock,
            'message': f"Emergency clock-in {'enabled' if staff.allow_emergency_clock else 'disabled'} for {staff.full_name}"
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/sites/<int:site_id>/standby', methods=['POST'])
@token_required
@admin_required
def set_site_standby_person(current_user, site_id):
    """Set the standby person for a site"""
    db = SessionLocal()
    try:
        site = db.query(Site).get(site_id)
        if not site:
            return jsonify({'error': 'Site not found'}), 404

        data = request.json or {}
        staff_id = data.get('staff_id')

        if staff_id:
            staff = db.query(StaffMember).get(staff_id)
            if not staff:
                return jsonify({'error': 'Staff member not found'}), 404
            site.standby_staff_id = staff_id
            staff_name = staff.full_name
        else:
            site.standby_staff_id = None
            staff_name = None

        db.commit()

        return jsonify({
            'success': True,
            'site_id': site_id,
            'site_name': site.name,
            'standby_staff_id': site.standby_staff_id,
            'standby_staff_name': staff_name,
            'message': f"Standby person {'set to ' + staff_name if staff_name else 'cleared'} for {site.name}"
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/standby/generate', methods=['POST'])
@token_required
@admin_required
def generate_standby_records(current_user):
    """Generate standby records for a no-work day"""
    db = SessionLocal()
    try:
        data = request.json or {}
        target_date = data.get('date')

        if target_date:
            standby_date = datetime.strptime(target_date, '%Y-%m-%d').date()
        else:
            standby_date = date.today()

        # Get sites with standby persons assigned
        sites_with_standby = db.query(Site).filter(
            Site.standby_staff_id.isnot(None),
            Site.is_active == True
        ).all()

        standby_rate = system_config.get('standby_daily_rate', 150.00)
        created = []

        for site in sites_with_standby:
            staff = db.query(StaffMember).get(site.standby_staff_id)
            if not staff or not staff.is_active:
                continue

            # Check if record already exists
            existing = db.execute(
                "SELECT id FROM standby_records WHERE staff_id = ? AND standby_date = ?",
                (site.standby_staff_id, standby_date)
            ).fetchone()

            if not existing:
                db.execute(
                    """INSERT INTO standby_records (staff_id, site_id, standby_date, daily_rate, status, notes)
                       VALUES (?, ?, ?, ?, 'standby', 'Auto-generated for no-work day')""",
                    (site.standby_staff_id, site.id, standby_date, standby_rate)
                )
                created.append({
                    'staff_id': site.standby_staff_id,
                    'staff_name': staff.full_name,
                    'site_name': site.name,
                    'rate': standby_rate
                })

        db.commit()

        return jsonify({
            'success': True,
            'date': standby_date.isoformat(),
            'standby_rate': standby_rate,
            'created_count': len(created),
            'records': created
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/standby/records')
@token_required
@admin_required
def get_standby_records(current_user):
    """Get standby records for reporting"""
    db = SessionLocal()
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        staff_id = request.args.get('staff_id', type=int)

        query = "SELECT sr.*, sm.first_name || ' ' || sm.last_name as staff_name, s.name as site_name FROM standby_records sr LEFT JOIN staff_members sm ON sr.staff_id = sm.id LEFT JOIN sites s ON sr.site_id = s.id WHERE 1=1"
        params = []

        if start_date:
            query += " AND sr.standby_date >= ?"
            params.append(start_date)
        if end_date:
            query += " AND sr.standby_date <= ?"
            params.append(end_date)
        if staff_id:
            query += " AND sr.staff_id = ?"
            params.append(staff_id)

        query += " ORDER BY sr.standby_date DESC"

        records = db.execute(query, params).fetchall()

        result = []
        for r in records:
            result.append({
                'id': r[0],
                'staff_id': r[1],
                'site_id': r[2],
                'standby_date': r[3],
                'daily_rate': r[4],
                'status': r[5],
                'worked_at': r[6],
                'notes': r[7],
                'created_at': r[8],
                'staff_name': r[9],
                'site_name': r[10]
            })

        return jsonify({
            'success': True,
            'records': result,
            'count': len(result)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# ===== NO WORK DAY MANAGEMENT =====

@app.route('/api/admin/no-work-days', methods=['GET'])
@token_required
@admin_required
def get_no_work_days(current_user):
    """Get all no-work days (admin only)"""
    db = SessionLocal()
    try:
        site_id = request.args.get('site_id', type=int)
        include_past = request.args.get('include_past', 'false').lower() == 'true'

        query = db.query(NoWorkDay)

        if site_id:
            # Site-specific or company-wide
            query = query.filter(or_(NoWorkDay.site_id == site_id, NoWorkDay.site_id.is_(None)))

        if not include_past:
            query = query.filter(NoWorkDay.no_work_date >= date.today())

        query = query.filter(NoWorkDay.is_active == True)
        query = query.order_by(NoWorkDay.no_work_date.asc())

        no_work_days = query.all()

        result = []
        for nwd in no_work_days:
            # Get acknowledgment count
            ack_count = db.query(NoWorkAcknowledgment).filter(
                NoWorkAcknowledgment.no_work_day_id == nwd.id
            ).count()

            # Get total staff count for this site (or all if company-wide)
            if nwd.site_id:
                staff_count = db.query(StaffMember).filter(
                    StaffMember.site_id == nwd.site_id,
                    StaffMember.is_active == True
                ).count()
            else:
                staff_count = db.query(StaffMember).filter(
                    StaffMember.is_active == True
                ).count()

            result.append({
                'id': nwd.id,
                'date': nwd.no_work_date.isoformat() if hasattr(nwd.no_work_date, 'isoformat') else str(nwd.no_work_date),
                'site_id': nwd.site_id,
                'site_name': nwd.site.name if nwd.site else 'All Sites',
                'day_type': nwd.day_type.value,
                'reason': nwd.reason,
                'message': nwd.message,
                'sms_sent': nwd.sms_sent,
                'sms_scheduled_for': nwd.sms_scheduled_for.strftime('%Y-%m-%d %H:%M') if nwd.sms_scheduled_for else None,
                'acknowledgments': ack_count,
                'total_staff': staff_count,
                'created_at': nwd.created_at.isoformat() if nwd.created_at else None
            })

        return jsonify({
            'success': True,
            'no_work_days': result,
            'count': len(result)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/no-work-days', methods=['POST'])
@token_required
@admin_required
def create_no_work_day(current_user):
    """Create a new no-work day notification (admin only)"""
    db = SessionLocal()
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Required fields
        dates = data.get('dates', [])  # Can be single date or list of dates
        if not dates:
            # Try single date field
            single_date = data.get('date')
            if single_date:
                dates = [single_date]
            else:
                return jsonify({'error': 'Date(s) required'}), 400

        reason = data.get('reason')
        if not reason:
            return jsonify({'error': 'Reason required'}), 400

        # Optional fields
        site_id = data.get('site_id')  # None = all sites
        day_type_str = data.get('day_type', 'other')
        message = data.get('message', '')
        send_sms = data.get('send_sms', True)

        # Validate day_type
        try:
            day_type = NoWorkDayType(day_type_str)
        except ValueError:
            day_type = NoWorkDayType.OTHER

        # Validate site exists if provided
        if site_id:
            site = db.query(Site).filter(Site.id == site_id).first()
            if not site:
                return jsonify({'error': 'Site not found'}), 404

        created_days = []

        for date_str in dates:
            # Parse date
            try:
                if isinstance(date_str, str):
                    no_work_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                else:
                    no_work_date = date_str
            except ValueError:
                return jsonify({'error': f'Invalid date format: {date_str}. Use YYYY-MM-DD'}), 400

            # Check if already exists
            existing = db.query(NoWorkDay).filter(
                NoWorkDay.no_work_date == no_work_date,
                NoWorkDay.site_id == site_id if site_id else NoWorkDay.site_id.is_(None),
                NoWorkDay.is_active == True
            ).first()

            if existing:
                # Skip if already exists
                continue

            # Create no-work day record
            no_work_day = NoWorkDay(
                no_work_date=no_work_date,
                site_id=site_id,
                day_type=day_type,
                reason=reason,
                message=message,
                created_by_id=current_user.id
            )

            db.add(no_work_day)
            db.flush()  # Get the ID

            created_days.append({
                'id': no_work_day.id,
                'date': no_work_date.isoformat()
            })

        if not created_days:
            return jsonify({'error': 'No new dates created (may already exist)'}), 400

        db.commit()

        # Send SMS if requested
        sms_results = []
        sms_scheduled_for = None
        if send_sms:
            # Get staff to notify - check both mobile and phone fields
            from sqlalchemy import or_
            staff_query = db.query(StaffMember).filter(
                StaffMember.is_active == True,
                or_(
                    StaffMember.mobile.isnot(None),
                    StaffMember.phone.isnot(None)
                )
            )

            if site_id:
                staff_query = staff_query.filter(StaffMember.site_id == site_id)

            staff_list = staff_query.all()

            # Format dates nicely for SMS
            if len(dates) == 1:
                date_text = datetime.strptime(dates[0], '%Y-%m-%d').strftime('%d %b %Y') if isinstance(dates[0], str) else dates[0].strftime('%d %b %Y')
            else:
                date_text = ', '.join([
                    datetime.strptime(d, '%Y-%m-%d').strftime('%d %b') if isinstance(d, str) else d.strftime('%d %b')
                    for d in dates
                ])

            site_text = f" at {site.name}" if site_id else ""

            # Format day type nicely (e.g., "wage_weekend" -> "WAGE WEEKEND")
            day_type_display = day_type.value.replace('_', ' ').upper()

            # Combine type and reason: "WAGE WEEKEND - PRE XMAS"
            sms_message = f"WAGEPRO: NO WORK{site_text} on {date_text}. {day_type_display} - {reason}"
            if message:
                sms_message += f". {message}"
            sms_message += ". Acknowledge on clock-in page."

            # Use SMSNotifier with bulk sending
            notifier = SMSNotifier()

            # Build bulk message list - prefer mobile over phone
            bulk_messages = []
            for staff in staff_list:
                phone_number = staff.mobile or staff.phone
                if phone_number:
                    bulk_messages.append({
                        'mobile': phone_number,
                        'message': sms_message
                    })
                    sms_results.append({
                        'staff_id': staff.id,
                        'name': staff.full_name,
                        'success': True  # Will be updated if bulk send fails
                    })

            # Send bulk SMS (will be scheduled if after 18:00)
            if bulk_messages:
                bulk_result = notifier.send_bulk_sms(bulk_messages)
                if not bulk_result.get('success'):
                    # Mark all as failed
                    for r in sms_results:
                        r['success'] = False
                        r['error'] = bulk_result.get('message', 'Bulk SMS failed')

                # Check if SMS was scheduled
                sms_scheduled_for = notifier.get_scheduled_time()

            # Update SMS sent flag
            for day_info in created_days:
                day = db.query(NoWorkDay).filter(NoWorkDay.id == day_info['id']).first()
                if day:
                    day.sms_sent = True
                    day.sms_sent_at = datetime.utcnow()
                    day.sms_scheduled_for = sms_scheduled_for

            db.commit()

        return jsonify({
            'success': True,
            'message': f'Created {len(created_days)} no-work day(s)',
            'created': created_days,
            'sms_sent': len([r for r in sms_results if r.get('success')]),
            'sms_failed': len([r for r in sms_results if not r.get('success')]),
            'sms_results': sms_results
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/no-work-days/<int:id>', methods=['DELETE'])
@token_required
@admin_required
def delete_no_work_day(current_user, id):
    """Cancel/delete a no-work day (admin only)"""
    db = SessionLocal()
    try:
        no_work_day = db.query(NoWorkDay).filter(NoWorkDay.id == id).first()

        if not no_work_day:
            return jsonify({'error': 'No-work day not found'}), 404

        # Soft delete - mark as inactive
        no_work_day.is_active = False
        db.commit()

        return jsonify({
            'success': True,
            'message': f'No-work day for {no_work_day.no_work_date} cancelled'
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/no-work-days/<int:id>/acknowledgments', methods=['GET'])
@token_required
@admin_required
def get_no_work_day_acknowledgments(current_user, id):
    """Get acknowledgment status for a no-work day (admin only)"""
    db = SessionLocal()
    try:
        no_work_day = db.query(NoWorkDay).filter(NoWorkDay.id == id).first()

        if not no_work_day:
            return jsonify({'error': 'No-work day not found'}), 404

        # Get all staff for this site (or all staff if company-wide)
        staff_query = db.query(StaffMember).filter(StaffMember.is_active == True)

        if no_work_day.site_id:
            staff_query = staff_query.filter(StaffMember.site_id == no_work_day.site_id)

        all_staff = staff_query.all()

        # Get acknowledgments
        acknowledgments = db.query(NoWorkAcknowledgment).filter(
            NoWorkAcknowledgment.no_work_day_id == id
        ).all()

        ack_staff_ids = {a.staff_id for a in acknowledgments}

        acknowledged = []
        not_acknowledged = []

        for staff in all_staff:
            staff_info = {
                'id': staff.id,
                'name': staff.full_name,
                'phone': staff.phone,
                'site': staff.site.name if staff.site else None
            }

            if staff.id in ack_staff_ids:
                # Find the acknowledgment
                ack = next((a for a in acknowledgments if a.staff_id == staff.id), None)
                staff_info['acknowledged_at'] = ack.acknowledged_at.isoformat() if ack else None
                acknowledged.append(staff_info)
            else:
                not_acknowledged.append(staff_info)

        return jsonify({
            'success': True,
            'no_work_day': {
                'id': no_work_day.id,
                'date': no_work_day.no_work_date.isoformat() if hasattr(no_work_day.no_work_date, 'isoformat') else str(no_work_day.no_work_date),
                'reason': no_work_day.reason
            },
            'acknowledged': acknowledged,
            'not_acknowledged': not_acknowledged,
            'summary': {
                'total': len(all_staff),
                'acknowledged': len(acknowledged),
                'pending': len(not_acknowledged)
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# ===== STAFF NO WORK DAY ENDPOINTS =====

@app.route('/api/staff/no-work-alerts', methods=['GET'])
def get_staff_no_work_alerts():
    """Get pending no-work alerts for a staff member (for clock-in page)"""
    db = SessionLocal()
    try:
        staff_id = request.args.get('staff_id', type=int)

        if not staff_id:
            return jsonify({'error': 'staff_id required'}), 400

        staff = db.query(StaffMember).filter(StaffMember.id == staff_id).first()

        if not staff:
            return jsonify({'error': 'Staff not found'}), 404

        # Get active no-work days for this staff member's site (or company-wide)
        # Only show upcoming or today's dates
        query = db.query(NoWorkDay).filter(
            NoWorkDay.is_active == True,
            NoWorkDay.no_work_date >= date.today(),
            or_(
                NoWorkDay.site_id == staff.site_id,
                NoWorkDay.site_id.is_(None)
            )
        ).order_by(NoWorkDay.no_work_date.asc())

        no_work_days = query.all()

        # Get acknowledgments by this staff member
        staff_acks = db.query(NoWorkAcknowledgment).filter(
            NoWorkAcknowledgment.staff_id == staff_id
        ).all()

        ack_day_ids = {a.no_work_day_id for a in staff_acks}

        alerts = []
        for nwd in no_work_days:
            alerts.append({
                'id': nwd.id,
                'date': nwd.no_work_date.isoformat() if hasattr(nwd.no_work_date, 'isoformat') else str(nwd.no_work_date),
                'date_formatted': nwd.no_work_date.strftime('%A, %d %B %Y') if hasattr(nwd.no_work_date, 'strftime') else str(nwd.no_work_date),
                'day_type': nwd.day_type.value,
                'reason': nwd.reason,
                'message': nwd.message,
                'site_name': nwd.site.name if nwd.site else 'All Sites',
                'acknowledged': nwd.id in ack_day_ids,
                'is_today': nwd.no_work_date == date.today() if hasattr(nwd.no_work_date, '__eq__') else str(nwd.no_work_date) == str(date.today())
            })

        # Check if today is a no-work day (to block clock-in)
        today_is_no_work = any(a['is_today'] for a in alerts)
        unacknowledged = [a for a in alerts if not a['acknowledged']]

        return jsonify({
            'success': True,
            'alerts': alerts,
            'unacknowledged_count': len(unacknowledged),
            'today_is_no_work': today_is_no_work,
            'block_clockin': today_is_no_work
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/staff/no-work-alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_no_work_alert(alert_id):
    """Acknowledge a no-work day alert"""
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        staff_id = data.get('staff_id')

        if not staff_id:
            return jsonify({'error': 'staff_id required'}), 400

        # Verify alert exists and is active
        no_work_day = db.query(NoWorkDay).filter(
            NoWorkDay.id == alert_id,
            NoWorkDay.is_active == True
        ).first()

        if not no_work_day:
            return jsonify({'error': 'No-work day not found'}), 404

        # Verify staff exists
        staff = db.query(StaffMember).filter(StaffMember.id == staff_id).first()

        if not staff:
            return jsonify({'error': 'Staff not found'}), 404

        # Check if already acknowledged
        existing = db.query(NoWorkAcknowledgment).filter(
            NoWorkAcknowledgment.no_work_day_id == alert_id,
            NoWorkAcknowledgment.staff_id == staff_id
        ).first()

        if existing:
            return jsonify({
                'success': True,
                'message': 'Already acknowledged',
                'acknowledged_at': existing.acknowledged_at.isoformat()
            })

        # Create acknowledgment
        ack = NoWorkAcknowledgment(
            no_work_day_id=alert_id,
            staff_id=staff_id,
            device_info=request.user_agent.string if request.user_agent else None
        )

        db.add(ack)
        db.commit()

        return jsonify({
            'success': True,
            'message': f'Acknowledged no-work day for {no_work_day.no_work_date}',
            'acknowledged_at': ack.acknowledged_at.isoformat()
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# ===== REWARDS & PENALTIES SYSTEM =====

def get_points_config(db, key, default=None):
    """Get a points configuration value"""
    config = db.query(PointsConfiguration).filter(PointsConfiguration.config_key == key).first()
    if config:
        # Try to convert to float/int/bool as appropriate
        val = config.config_value
        if val.lower() in ('true', 'false'):
            return val.lower() == 'true'
        try:
            if '.' in val:
                return float(val)
            return int(val)
        except ValueError:
            return val
    return default


@app.route('/api/admin/points-config', methods=['GET'])
@token_required
@admin_required
def get_all_points_config(current_user):
    """Get all points configuration settings"""
    db = SessionLocal()
    try:
        configs = db.query(PointsConfiguration).all()
        return jsonify({
            'success': True,
            'config': {c.config_key: {
                'value': c.config_value,
                'description': c.description,
                'updated_at': c.updated_at.isoformat() if c.updated_at else None
            } for c in configs}
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/points-config', methods=['PUT'])
@token_required
@admin_required
def update_points_config(current_user):
    """Update points configuration settings"""
    db = SessionLocal()
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        updated = []
        for key, value in data.items():
            config = db.query(PointsConfiguration).filter(PointsConfiguration.config_key == key).first()
            if config:
                config.config_value = str(value)
                config.updated_by_id = current_user.id
                updated.append(key)

        db.commit()
        return jsonify({
            'success': True,
            'message': f'Updated {len(updated)} settings',
            'updated': updated
        })
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/standby-config', methods=['GET'])
@token_required
@admin_required
def get_standby_config(current_user):
    """Get standby daily rate configuration"""
    return jsonify({
        'success': True,
        'standby_daily_rate': system_config.get('standby_daily_rate', 150.00)
    })


@app.route('/api/admin/standby-config', methods=['PUT'])
@token_required
@admin_required
def update_standby_config(current_user):
    """Update standby daily rate configuration"""
    data = request.get_json()
    if not data or 'standby_daily_rate' not in data:
        return jsonify({'error': 'standby_daily_rate required'}), 400

    try:
        rate = float(data['standby_daily_rate'])
        if rate < 0:
            return jsonify({'error': 'Rate cannot be negative'}), 400

        system_config['standby_daily_rate'] = rate
        return jsonify({
            'success': True,
            'message': f'Standby rate updated to R{rate:.2f}',
            'standby_daily_rate': rate
        })
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid rate value'}), 400


@app.route('/api/admin/rewards-penalties', methods=['GET'])
@token_required
@admin_required
def get_rewards_penalties(current_user):
    """Get rewards and penalties with optional filters"""
    db = SessionLocal()
    try:
        # Query params
        period_id = request.args.get('period_id', type=int)
        status = request.args.get('status')
        staff_id = request.args.get('staff_id', type=int)
        site_id = request.args.get('site_id', type=int)
        category = request.args.get('category')
        rp_type = request.args.get('type')  # 'reward' or 'penalty'

        query = db.query(StaffRewardPenalty)

        if period_id:
            query = query.filter(StaffRewardPenalty.pay_period_id == period_id)
        if status:
            query = query.filter(StaffRewardPenalty.status == status)
        if rp_type == 'reward':
            query = query.filter(StaffRewardPenalty.points > 0)
        elif rp_type == 'penalty':
            query = query.filter(StaffRewardPenalty.points < 0)
        if staff_id:
            query = query.filter(StaffRewardPenalty.staff_id == staff_id)
        if site_id:
            # Include both site-wide rewards AND individual staff rewards for staff at this site
            from sqlalchemy import or_
            staff_at_site = db.query(StaffMember.id).filter(StaffMember.site_id == site_id).subquery()
            query = query.filter(or_(
                StaffRewardPenalty.site_id == site_id,  # Site-wide rewards
                StaffRewardPenalty.staff_id.in_(staff_at_site)  # Individual rewards for staff at site
            ))
        if category:
            query = query.filter(StaffRewardPenalty.category == category)

        # Order by created date desc
        query = query.order_by(StaffRewardPenalty.created_at.desc())

        items = query.all()

        # Get points to rand rate for display
        rate = get_points_config(db, 'points_to_rand_rate', 5.0)

        result = []
        for item in items:
            result.append({
                'id': item.id,
                'staff_id': item.staff_id,
                'staff_name': item.staff.full_name if item.staff else None,
                'site_id': item.site_id,
                'site_name': item.site.name if item.site else None,
                'target_type': item.target_type,
                'pay_period_id': item.pay_period_id,
                'category': item.category.value,
                'points': item.points,
                'rand_value': abs(item.points) * rate,
                'is_reward': item.is_reward,
                'is_penalty': item.is_penalty,
                'source': item.source.value,
                'description': item.description,
                'status': item.status.value,
                'created_at': item.created_at.isoformat() if item.created_at else None,
                'created_by': item.created_by.full_name if item.created_by else 'System',
                'approved_at': item.approved_at.isoformat() if item.approved_at else None,
                'approved_by': item.approved_by.full_name if item.approved_by else None,
                'reference_count': item.reference_count
            })

        return jsonify({
            'success': True,
            'items': result,
            'count': len(result),
            'points_to_rand_rate': rate
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/rewards-penalties', methods=['POST'])
@token_required
@admin_required
def create_reward_penalty(current_user):
    """Create a new reward or penalty"""
    db = SessionLocal()
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Required fields
        category = data.get('category')
        points = data.get('points')
        pay_period_id = data.get('pay_period_id')

        if not category:
            return jsonify({'error': 'Category required'}), 400
        if points is None:
            return jsonify({'error': 'Points required'}), 400
        if not pay_period_id:
            return jsonify({'error': 'Pay period required'}), 400

        # Validate category
        try:
            category_enum = RewardPenaltyCategory(category)
        except ValueError:
            return jsonify({'error': f'Invalid category: {category}'}), 400

        # Optional fields
        staff_id = data.get('staff_id')
        site_id = data.get('site_id')
        description = data.get('description', '')

        # Validate targets
        if staff_id:
            staff = db.query(StaffMember).filter(StaffMember.id == staff_id).first()
            if not staff:
                return jsonify({'error': 'Staff member not found'}), 404

        if site_id and not staff_id:
            site = db.query(Site).filter(Site.id == site_id).first()
            if not site:
                return jsonify({'error': 'Site not found'}), 404

        # Validate pay period
        period = db.query(PayPeriod).filter(PayPeriod.id == pay_period_id).first()
        if not period:
            return jsonify({'error': 'Pay period not found'}), 404

        # Create the reward/penalty
        item = StaffRewardPenalty(
            staff_id=staff_id,
            site_id=site_id if not staff_id else None,  # Site only if not individual
            pay_period_id=pay_period_id,
            category=category_enum,
            points=int(points),
            source=RewardPenaltySource.MANUAL,
            description=description,
            status=RewardPenaltyStatus.PENDING,
            created_by_id=current_user.id
        )

        db.add(item)
        db.commit()

        return jsonify({
            'success': True,
            'message': f'{"Reward" if points > 0 else "Penalty"} created successfully',
            'id': item.id
        })
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/rewards-penalties/<int:id>/approve', methods=['POST'])
@token_required
@admin_required
def approve_reward_penalty(current_user, id):
    """Approve a pending reward/penalty"""
    db = SessionLocal()
    try:
        item = db.query(StaffRewardPenalty).filter(StaffRewardPenalty.id == id).first()
        if not item:
            return jsonify({'error': 'Item not found'}), 404

        if item.status != RewardPenaltyStatus.PENDING:
            return jsonify({'error': f'Cannot approve item with status: {item.status.value}'}), 400

        item.status = RewardPenaltyStatus.APPROVED
        item.approved_by_id = current_user.id
        item.approved_at = datetime.utcnow()

        db.commit()

        return jsonify({
            'success': True,
            'message': 'Item approved'
        })
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/rewards-penalties/<int:id>/cancel', methods=['POST'])
@token_required
@admin_required
def cancel_reward_penalty(current_user, id):
    """Cancel a pending or approved reward/penalty"""
    db = SessionLocal()
    try:
        item = db.query(StaffRewardPenalty).filter(StaffRewardPenalty.id == id).first()
        if not item:
            return jsonify({'error': 'Item not found'}), 404

        if item.status == RewardPenaltyStatus.APPLIED:
            return jsonify({'error': 'Cannot cancel an already applied item'}), 400

        item.status = RewardPenaltyStatus.CANCELLED
        db.commit()

        return jsonify({
            'success': True,
            'message': 'Item cancelled'
        })
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/rewards-penalties/summary', methods=['GET'])
@token_required
@admin_required
def get_rewards_penalties_summary(current_user):
    """Get summary statistics for rewards and penalties"""
    db = SessionLocal()
    try:
        period_id = request.args.get('period_id', type=int)

        # Get current period if not specified
        if not period_id:
            period = db.query(PayPeriod).filter(
                PayPeriod.status.in_([PayPeriodStatus.ACTIVE, PayPeriodStatus.DRAFT])
            ).order_by(PayPeriod.start_date.desc()).first()
            if period:
                period_id = period.id

        # Base query
        query = db.query(StaffRewardPenalty)
        if period_id:
            query = query.filter(StaffRewardPenalty.pay_period_id == period_id)

        all_items = query.all()

        # Calculate stats
        pending_rewards = sum(1 for i in all_items if i.status == RewardPenaltyStatus.PENDING and i.is_reward)
        pending_penalties = sum(1 for i in all_items if i.status == RewardPenaltyStatus.PENDING and i.is_penalty)
        approved_rewards = sum(1 for i in all_items if i.status == RewardPenaltyStatus.APPROVED and i.is_reward)
        approved_penalties = sum(1 for i in all_items if i.status == RewardPenaltyStatus.APPROVED and i.is_penalty)

        total_reward_points = sum(i.points for i in all_items if i.status in [RewardPenaltyStatus.PENDING, RewardPenaltyStatus.APPROVED] and i.is_reward)
        total_penalty_points = sum(abs(i.points) for i in all_items if i.status in [RewardPenaltyStatus.PENDING, RewardPenaltyStatus.APPROVED] and i.is_penalty)

        rate = get_points_config(db, 'points_to_rand_rate', 5.0)

        return jsonify({
            'success': True,
            'period_id': period_id,
            'pending_rewards': pending_rewards,
            'pending_penalties': pending_penalties,
            'approved_rewards': approved_rewards,
            'approved_penalties': approved_penalties,
            'total_pending': pending_rewards + pending_penalties,
            'total_reward_points': total_reward_points,
            'total_penalty_points': total_penalty_points,
            'total_reward_rand': total_reward_points * rate,
            'total_penalty_rand': total_penalty_points * rate,
            'points_to_rand_rate': rate
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/staff/my-points', methods=['GET'])
def get_staff_points():
    """Get points summary for a staff member (for clock-in page)

    Accepts either:
    - staff_id query parameter
    - Authorization Bearer token (from clock-in page)
    """
    db = SessionLocal()
    try:
        staff_id = request.args.get('staff_id', type=int)

        # Try to get staff_id from token if not provided as query param
        if not staff_id:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
                try:
                    payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
                    staff_id = payload.get('staff_id')
                except:
                    pass

        if not staff_id:
            return jsonify({'error': 'staff_id required'}), 400

        # Get current open period
        period = db.query(PayPeriod).filter(
            PayPeriod.status == PayPeriodStatus.OPEN
        ).order_by(PayPeriod.start_date.desc()).first()

        if not period:
            return jsonify({
                'success': True,
                'total_rewards': 0,
                'total_penalties': 0,
                'net_points': 0,
                'rand_value': 0,
                'period_name': 'No active period'
            })

        # Get staff member for hourly rate
        staff = db.query(StaffMember).filter(StaffMember.id == staff_id).first()
        if not staff:
            return jsonify({'error': 'Staff not found'}), 404

        # Get items for this staff member in current period
        # Explicitly exclude CANCELLED and APPLIED items
        items = db.query(StaffRewardPenalty).filter(
            StaffRewardPenalty.pay_period_id == period.id,
            StaffRewardPenalty.staff_id == staff_id,
            StaffRewardPenalty.status.notin_([RewardPenaltyStatus.CANCELLED, RewardPenaltyStatus.APPLIED])
        ).all()

        total_rewards = sum(i.points for i in items if i.points > 0)
        total_penalties = sum(abs(i.points) for i in items if i.points < 0)
        net_points = total_rewards - total_penalties

        # FAIR SYSTEM: 10 points = 1 hour of individual's pay rate
        hourly_rate = staff.hourly_rate or (staff.daily_rate / 8 if staff.daily_rate else 0)
        points_per_hour = float(get_points_config(db, 'points_per_hour', 10))
        point_value = hourly_rate / points_per_hour if points_per_hour > 0 else 0
        rand_value = net_points * point_value

        return jsonify({
            'success': True,
            'period_id': period.id,
            'period_name': f"{period.start_date.strftime('%d/%m')} - {period.end_date.strftime('%d/%m/%Y')}",
            'total_rewards': total_rewards,
            'total_penalties': total_penalties,
            'net_points': net_points,
            'rand_value': rand_value,
            'hourly_rate': hourly_rate,
            'point_value': point_value,
            'items': [{
                'category': i.category.value.replace('_', ' ').title(),
                'points': i.points,
                'description': i.description,
                'status': i.status.value
            } for i in items]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# ===== PROGRESS PICTURES API =====

@app.route('/api/admin/progress-pictures', methods=['GET'])
@token_required
@admin_required
def get_progress_pictures(current_user):
    """Get all progress pictures with optional filters"""
    db = SessionLocal()
    try:
        # Filters
        staff_id = request.args.get('staff_id', type=int)
        date_str = request.args.get('date')
        status = request.args.get('status')

        query = db.query(ProgressPicture).join(StaffMember)

        if staff_id:
            query = query.filter(ProgressPicture.staff_id == staff_id)

        if date_str:
            try:
                filter_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                query = query.filter(
                    ProgressPicture.taken_at >= datetime.combine(filter_date, datetime.min.time()),
                    ProgressPicture.taken_at < datetime.combine(filter_date + timedelta(days=1), datetime.min.time())
                )
            except:
                pass

        if status:
            query = query.filter(ProgressPicture.status == status)

        pictures = query.order_by(ProgressPicture.taken_at.desc()).limit(100).all()

        result = []
        for pic in pictures:
            staff = db.query(StaffMember).get(pic.staff_id)
            # Convert file path to URL
            url_path = pic.file_path.replace('\\', '/').replace('C:/WAGEPRO/', '/').replace('C:\\WAGEPRO\\', '/')

            result.append({
                'id': pic.id,
                'staff_id': pic.staff_id,
                'staff_name': staff.full_name if staff else 'Unknown',
                'attendance_id': pic.attendance_id,
                'filename': pic.filename,
                'file_path': pic.file_path,
                'url': url_path,
                'taken_at': pic.taken_at.isoformat() if pic.taken_at else None,
                'description': pic.description,
                'status': pic.status.value if pic.status else 'PENDING',
                'latitude': pic.latitude,
                'longitude': pic.longitude
            })

        return jsonify({
            'success': True,
            'pictures': result,
            'count': len(result)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/progress-pictures/<int:pic_id>/review', methods=['POST'])
@token_required
@admin_required
def review_progress_picture(current_user, pic_id):
    """Approve or reject a progress picture"""
    db = SessionLocal()
    try:
        data = request.json
        action = data.get('action')  # 'approve' or 'reject'
        notes = data.get('notes', '')

        pic = db.query(ProgressPicture).get(pic_id)
        if not pic:
            return jsonify({'error': 'Picture not found'}), 404

        if action == 'approve':
            pic.status = PictureStatus.APPROVED
        elif action == 'reject':
            pic.status = PictureStatus.REJECTED
        else:
            return jsonify({'error': 'Invalid action. Use approve or reject'}), 400

        pic.reviewed_by_id = current_user.id
        pic.reviewed_at = datetime.now()
        pic.review_notes = notes

        db.commit()

        return jsonify({
            'success': True,
            'message': f'Picture {action}d successfully'
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/progress-pictures')
def progress_pictures_page():
    """Admin page to view progress pictures (auth checked client-side)"""
    return render_template('progress_pictures.html')


# ===== WORKPRO MOBILE APIs =====
# These APIs interact with WORKPRO database for mobile manager features

WORKPRO_DB = 'C:/WORKPRO/workpro.db'

def get_workpro_db():
    """Get connection to WORKPRO database"""
    import sqlite3
    if not os.path.exists(WORKPRO_DB):
        return None
    return sqlite3.connect(WORKPRO_DB)


@app.route('/api/workpro/projects')
@token_required
def get_workpro_projects(current_user):
    """Get projects from WORKPRO for dropdown"""
    conn = get_workpro_db()
    if not conn:
        return jsonify({'error': 'WORKPRO database not available'}), 500

    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, name, code, status
            FROM projects
            WHERE status IN ('ACTIVE', 'IN_PROGRESS', 'PENDING', 'ON_HOLD')
            ORDER BY name
        ''')
        projects = [{'id': r[0], 'name': r[1], 'code': r[2], 'status': r[3]} for r in cursor.fetchall()]
        return jsonify({'projects': projects})
    finally:
        conn.close()


@app.route('/api/workpro/tasks')
@token_required
def get_workpro_tasks(current_user):
    """Get tasks from WORKPRO, optionally filtered by project"""
    conn = get_workpro_db()
    if not conn:
        return jsonify({'error': 'WORKPRO database not available'}), 500

    try:
        cursor = conn.cursor()
        project_id = request.args.get('project_id')

        if project_id:
            cursor.execute('''
                SELECT t.id, t.title, t.status, t.project_id, p.name as project_name
                FROM tasks t
                LEFT JOIN projects p ON t.project_id = p.id
                WHERE t.project_id = ? AND t.status != 'CANCELLED'
                ORDER BY t.title
            ''', (project_id,))
        else:
            cursor.execute('''
                SELECT t.id, t.title, t.status, t.project_id, p.name as project_name
                FROM tasks t
                LEFT JOIN projects p ON t.project_id = p.id
                WHERE t.status != 'CANCELLED'
                ORDER BY p.name, t.title
            ''')

        tasks = [{'id': r[0], 'title': r[1], 'status': r[2], 'project_id': r[3], 'project_name': r[4]} for r in cursor.fetchall()]
        return jsonify({'tasks': tasks})
    finally:
        conn.close()


@app.route('/api/workpro/projects', methods=['POST'])
@token_required
def create_workpro_project(current_user):
    """Quick create a project in WORKPRO"""
    conn = get_workpro_db()
    if not conn:
        return jsonify({'error': 'WORKPRO database not available'}), 500

    try:
        data = request.json
        name = data.get('name', '').strip()
        if not name:
            return jsonify({'error': 'Project name is required'}), 400

        cursor = conn.cursor()
        now = datetime.now().isoformat()

        # Generate project code
        cursor.execute("SELECT COUNT(*) FROM projects WHERE code LIKE 'PROJ-" + str(date.today().year) + "-%'")
        count = cursor.fetchone()[0] + 1
        code = f"PROJ-{date.today().year}-{count:03d}"

        # Insert with minimal required fields (using defaults for others)
        cursor.execute('''
            INSERT INTO projects (
                name, code, description, status, priority,
                project_manager_id, start_date, target_end_date, actual_end_date,
                estimated_hours, estimated_budget, estimated_labor_cost, estimated_material_cost,
                notes, created_at, updated_at, site_id,
                gps_latitude, gps_longitude, gps_radius_meters
            ) VALUES (?, ?, ?, 'ACTIVE', 'normal', 1, ?, ?, ?, 0, 0, 0, 0, '', ?, ?, 1, 0, 0, 100)
        ''', (name, code, name, now, now, now, now, now))

        conn.commit()
        project_id = cursor.lastrowid

        return jsonify({
            'success': True,
            'project': {'id': project_id, 'name': name, 'code': code}
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@app.route('/api/workpro/tasks', methods=['POST'])
@token_required
def create_workpro_task(current_user):
    """Quick create a task in WORKPRO"""
    conn = get_workpro_db()
    if not conn:
        return jsonify({'error': 'WORKPRO database not available'}), 500

    try:
        data = request.json
        title = data.get('title', '').strip()
        project_id = data.get('project_id')

        if not title:
            return jsonify({'error': 'Task title is required'}), 400
        if not project_id:
            return jsonify({'error': 'Project is required'}), 400

        cursor = conn.cursor()
        now = datetime.now().isoformat()

        # Insert task with all required NOT NULL fields
        cursor.execute('''
            INSERT INTO tasks (
                project_id, title, description, status, priority,
                subtask_level, display_order, created_by_id,
                actual_hours, actual_labor_cost, actual_material_cost, progress_percentage,
                created_at, updated_at
            ) VALUES (?, ?, '', 'PENDING', 'NORMAL', 0, 0, 1, 0, 0, 0, 0, ?, ?)
        ''', (project_id, title, now, now))

        conn.commit()
        task_id = cursor.lastrowid

        return jsonify({
            'success': True,
            'task': {'id': task_id, 'title': title, 'project_id': project_id}
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@app.route('/api/workpro/vendors')
@token_required
def get_vendors(current_user):
    """Get active vendors/suppliers from WORKPRO"""
    conn = get_workpro_db()
    if not conn:
        return jsonify({'error': 'WORKPRO database not available'}), 500

    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, company_name, contact_phone
            FROM vendors
            WHERE is_active = 1
            ORDER BY company_name
        ''')

        vendors = []
        for v in cursor.fetchall():
            vendors.append({
                'id': v[0],
                'name': v[1],
                'phone': v[2]
            })

        return jsonify({'vendors': vendors})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@app.route('/api/workpro/shopping-list')
@token_required
def get_shopping_list(current_user):
    """Get shopping list items from WORKPRO"""
    conn = get_workpro_db()
    if not conn:
        return jsonify({'error': 'WORKPRO database not available'}), 500

    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT s.id, m.name as material_name, s.quantity, s.priority, s.status,
                   p.name as project_name, s.notes, s.added_at
            FROM shopping_list_items s
            LEFT JOIN materials m ON s.material_id = m.id
            LEFT JOIN projects p ON s.project_id = p.id
            WHERE s.status IN ('requested', 'ordered')
            ORDER BY
                CASE s.priority
                    WHEN 'urgent' THEN 1
                    WHEN 'next_week' THEN 2
                    WHEN 'next_month' THEN 3
                    ELSE 4
                END,
                s.added_at DESC
        ''')

        items = []
        for r in cursor.fetchall():
            items.append({
                'id': r[0],
                'material_name': r[1],
                'quantity': r[2],
                'priority': r[3],
                'status': r[4],
                'project_name': r[5],
                'notes': r[6],
                'added_at': r[7]
            })

        return jsonify({'items': items})
    finally:
        conn.close()


@app.route('/api/workpro/shopping-list', methods=['POST'])
@token_required
def add_shopping_list_item(current_user):
    """Add item to shopping list in WORKPRO"""
    conn = get_workpro_db()
    if not conn:
        return jsonify({'error': 'WORKPRO database not available'}), 500

    try:
        data = request.json
        material_name = data.get('material_name', '').strip()
        quantity = data.get('quantity', 1)
        priority = data.get('priority', 'normal')  # urgent, next_week, next_month, normal
        project_id = data.get('project_id')
        vendor_id = data.get('vendor_id')  # Optional supplier
        notes = data.get('notes', '').strip()

        if not material_name:
            return jsonify({'error': 'Item name is required'}), 400

        cursor = conn.cursor()
        now = datetime.now().isoformat()

        # Check if material exists, create if not
        cursor.execute('SELECT id FROM materials WHERE name = ?', (material_name,))
        material = cursor.fetchone()

        if material:
            material_id = material[0]
        else:
            # Create new material with all NOT NULL columns
            cursor.execute('''
                INSERT INTO materials (name, code, description, unit, category_id,
                    minimum_stock, vendor_id, unit_cost, created_at, updated_at,
                    is_active, current_stock, is_service, item_type)
                VALUES (?, ?, '', 'EACH', 1, 0, ?, 0, ?, ?, 1, 0, 0, 'material')
            ''', (material_name, material_name[:20].upper().replace(' ', '-'), vendor_id or 1, now, now))
            material_id = cursor.lastrowid

        # Add to shopping list (include all NOT NULL columns)
        cursor.execute('''
            INSERT INTO shopping_list_items (
                material_id, quantity, priority, status, source,
                project_id, ordered_by_id, actual_quantity, actual_unit_cost,
                actual_total_cost, vendor_id, notes, added_at, added_by_id,
                is_purchased
            ) VALUES (?, ?, ?, 'requested', 'project', ?, 1, 0, 0, 0, ?, ?, ?, 1, 0)
        ''', (material_id, quantity, priority, project_id or 1, vendor_id or 1, notes, now))

        conn.commit()
        item_id = cursor.lastrowid

        return jsonify({
            'success': True,
            'item': {'id': item_id, 'material_name': material_name, 'priority': priority}
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@app.route('/api/workpro/materials/search')
@token_required
def search_materials(current_user):
    """Search materials/inventory in WORKPRO"""
    conn = get_workpro_db()
    if not conn:
        return jsonify({'error': 'WORKPRO database not available'}), 500

    try:
        query = request.args.get('q', '').strip()
        cursor = conn.cursor()

        if query:
            cursor.execute('''
                SELECT id, name, code, current_stock, minimum_stock, unit, unit_cost
                FROM materials
                WHERE is_active = 1 AND (name LIKE ? OR code LIKE ?)
                ORDER BY name
                LIMIT 50
            ''', (f'%{query}%', f'%{query}%'))
        else:
            cursor.execute('''
                SELECT id, name, code, current_stock, minimum_stock, unit, unit_cost
                FROM materials
                WHERE is_active = 1
                ORDER BY name
                LIMIT 50
            ''')

        materials = []
        for r in cursor.fetchall():
            materials.append({
                'id': r[0],
                'name': r[1],
                'code': r[2],
                'current_stock': r[3] or 0,
                'minimum_stock': r[4] or 0,
                'unit': r[5],
                'unit_cost': r[6] or 0,
                'low_stock': (r[3] or 0) < (r[4] or 0)
            })

        return jsonify({'materials': materials})
    finally:
        conn.close()


@app.route('/api/workpro/shopping-list/pending')
@token_required
def get_pending_items(current_user):
    """Get shopping list items pending receipt (ordered but not received)"""
    conn = get_workpro_db()
    if not conn:
        return jsonify({'error': 'WORKPRO database not available'}), 500

    try:
        cursor = conn.cursor()

        # Add receipt_photo column if not exists
        try:
            cursor.execute('ALTER TABLE shopping_list_items ADD COLUMN receipt_photo TEXT')
            conn.commit()
        except:
            pass  # Column already exists

        cursor.execute('''
            SELECT s.id, m.name as material_name, s.quantity, s.priority, s.status,
                   p.name as project_name, s.notes, s.ordered_at
            FROM shopping_list_items s
            LEFT JOIN materials m ON s.material_id = m.id
            LEFT JOIN projects p ON s.project_id = p.id
            WHERE s.status IN ('requested', 'ordered')
            ORDER BY s.ordered_at DESC, s.added_at DESC
        ''')

        items = []
        for r in cursor.fetchall():
            items.append({
                'id': r[0],
                'material_name': r[1],
                'quantity': r[2],
                'priority': r[3],
                'status': r[4],
                'project_name': r[5],
                'notes': r[6],
                'ordered_at': r[7]
            })

        return jsonify({'items': items})
    finally:
        conn.close()


# Configure receipt photos upload folder
RECEIPT_UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads', 'receipts')
os.makedirs(RECEIPT_UPLOAD_FOLDER, exist_ok=True)


@app.route('/api/workpro/shopping-list/<int:item_id>/receive', methods=['POST'])
@token_required
def receive_shopping_item(current_user, item_id):
    """Mark shopping list item as received and update inventory"""
    conn = get_workpro_db()
    if not conn:
        return jsonify({'error': 'WORKPRO database not available'}), 500

    try:
        # Handle both JSON and form data (for file upload)
        if request.content_type and 'multipart/form-data' in request.content_type:
            actual_quantity = float(request.form.get('quantity', 0)) or None
            unit_cost = float(request.form.get('unit_cost', 0))
            photo_file = request.files.get('photo')
        else:
            data = request.json or {}
            actual_quantity = data.get('quantity')
            unit_cost = data.get('unit_cost', 0)
            photo_file = None

        cursor = conn.cursor()
        now = datetime.now().isoformat()
        today = date.today()

        # Get the shopping item and material_id (join with materials to get name)
        cursor.execute('''
            SELECT s.material_id, s.quantity, m.name as material_name
            FROM shopping_list_items s
            LEFT JOIN materials m ON s.material_id = m.id
            WHERE s.id = ?
        ''', (item_id,))
        item = cursor.fetchone()
        if not item:
            return jsonify({'error': 'Item not found'}), 404

        material_id = item[0]
        material_name = item[2] or 'Unknown'
        if actual_quantity is None:
            actual_quantity = item[1]  # Use ordered quantity if not specified

        # Handle photo upload
        photo_path = None
        if photo_file and photo_file.filename:
            # Create date-based subfolder
            date_folder = os.path.join(RECEIPT_UPLOAD_FOLDER, today.isoformat())
            os.makedirs(date_folder, exist_ok=True)

            # Generate unique filename
            ext = os.path.splitext(photo_file.filename)[1] or '.jpg'
            unique_filename = f"receipt_{item_id}_{datetime.now().strftime('%H%M%S')}{ext}"
            file_path = os.path.join(date_folder, unique_filename)
            photo_file.save(file_path)
            photo_path = f"receipts/{today.isoformat()}/{unique_filename}"

        # Update shopping list item as received
        cursor.execute('''
            UPDATE shopping_list_items
            SET status = 'received',
                received_at = ?,
                received_by_id = 1,
                actual_quantity = ?,
                actual_unit_cost = ?,
                actual_total_cost = ?,
                receipt_photo = ?
            WHERE id = ?
        ''', (now, actual_quantity, unit_cost, actual_quantity * unit_cost, photo_path, item_id))

        # Update material stock (add to current_stock)
        if material_id:
            cursor.execute('''
                UPDATE materials
                SET current_stock = COALESCE(current_stock, 0) + ?,
                    last_purchase_cost = ?,
                    last_purchase_date = ?,
                    updated_at = ?
                WHERE id = ?
            ''', (actual_quantity, unit_cost, now, now, material_id))

        conn.commit()

        # Get material name for response
        new_stock = 0
        if material_id:
            cursor.execute('SELECT name, current_stock FROM materials WHERE id = ?', (material_id,))
            material = cursor.fetchone()
            if material:
                material_name = material[0]
                new_stock = material[1]

        return jsonify({
            'success': True,
            'message': f'Received {actual_quantity} x {material_name}',
            'new_stock': new_stock,
            'photo_saved': photo_path is not None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@app.route('/uploads/receipts/<path:filename>')
def serve_receipt_photo(filename):
    """Serve uploaded receipt photos"""
    return send_from_directory(RECEIPT_UPLOAD_FOLDER, filename)


@app.route('/api/workpro/materials/<int:material_id>/use', methods=['POST'])
@token_required
def use_material(current_user, material_id):
    """Deduct material from inventory (items used)"""
    conn = get_workpro_db()
    if not conn:
        return jsonify({'error': 'WORKPRO database not available'}), 500

    try:
        data = request.json
        quantity = data.get('quantity', 1)
        project_id = data.get('project_id')
        task_id = data.get('task_id')
        notes = data.get('notes', '')

        if quantity <= 0:
            return jsonify({'error': 'Quantity must be positive'}), 400

        cursor = conn.cursor()
        now = datetime.now().isoformat()

        # Check current stock
        cursor.execute('SELECT name, current_stock, unit FROM materials WHERE id = ?', (material_id,))
        material = cursor.fetchone()
        if not material:
            return jsonify({'error': 'Material not found'}), 404

        name, current_stock, unit = material
        current_stock = current_stock or 0

        if current_stock < quantity:
            return jsonify({
                'error': f'Insufficient stock. Available: {current_stock} {unit}',
                'current_stock': current_stock
            }), 400

        # Deduct from stock
        new_stock = current_stock - quantity
        cursor.execute('''
            UPDATE materials
            SET current_stock = ?,
                updated_at = ?
            WHERE id = ?
        ''', (new_stock, now, material_id))

        # If linked to a task, update task_materials
        if task_id:
            cursor.execute('''
                INSERT INTO task_materials (task_id, material_id, actual_quantity, notes)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(task_id, material_id) DO UPDATE SET
                    actual_quantity = actual_quantity + ?,
                    notes = notes || ' | ' || ?
            ''', (task_id, material_id, quantity, notes, quantity, notes))

        conn.commit()

        return jsonify({
            'success': True,
            'message': f'Used {quantity} {unit} of {name}',
            'previous_stock': current_stock,
            'new_stock': new_stock
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@app.route('/api/workpro/materials/usage-log')
@token_required
def get_usage_log(current_user):
    """Get recent material usage (from task_materials)"""
    conn = get_workpro_db()
    if not conn:
        return jsonify({'error': 'WORKPRO database not available'}), 500

    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT tm.id, m.name as material_name, tm.actual_quantity, m.unit,
                   t.title as task_title, p.name as project_name, tm.notes
            FROM task_materials tm
            JOIN materials m ON tm.material_id = m.id
            LEFT JOIN tasks t ON tm.task_id = t.id
            LEFT JOIN projects p ON t.project_id = p.id
            WHERE tm.actual_quantity > 0
            ORDER BY tm.id DESC
            LIMIT 50
        ''')

        items = []
        for r in cursor.fetchall():
            items.append({
                'id': r[0],
                'material_name': r[1],
                'quantity': r[2],
                'unit': r[3],
                'task_title': r[4],
                'project_name': r[5],
                'notes': r[6]
            })

        return jsonify({'items': items})
    finally:
        conn.close()


# ===== PRODUCTIVITY API =====

@app.route('/api/productivity')
@token_required
def get_productivity_data(current_user):
    """
    Get productivity data - hours and costs by project/staff/day
    Query params:
        - period: today, yesterday, week, lastweek, month, custom
        - date_from, date_to: for custom period
        - project_id: filter by project
        - staff_id: filter by staff
        - group_by: project, staff, day
    """
    db = SessionLocal()
    try:
        # Parse filters
        period = request.args.get('period', 'week')
        project_id = request.args.get('project_id')
        staff_id = request.args.get('staff_id')
        group_by = request.args.get('group_by', 'project')

        # Calculate date range
        today = date.today()
        if period == 'today':
            date_from = today
            date_to = today
        elif period == 'yesterday':
            date_from = today - timedelta(days=1)
            date_to = today - timedelta(days=1)
        elif period == 'week':
            # Monday to today
            date_from = today - timedelta(days=today.weekday())
            date_to = today
        elif period == 'lastweek':
            # Last Monday to last Sunday
            last_monday = today - timedelta(days=today.weekday() + 7)
            date_from = last_monday
            date_to = last_monday + timedelta(days=6)
        elif period == 'month':
            date_from = today.replace(day=1)
            date_to = today
        elif period == 'custom':
            date_from_str = request.args.get('date_from')
            date_to_str = request.args.get('date_to')
            if date_from_str and date_to_str:
                date_from = datetime.strptime(date_from_str, '%Y-%m-%d').date()
                date_to = datetime.strptime(date_to_str, '%Y-%m-%d').date()
            else:
                date_from = today - timedelta(days=7)
                date_to = today
        else:
            date_from = today - timedelta(days=7)
            date_to = today

        # Build query for attendance with project data
        query = db.query(WorkerAttendance).filter(
            WorkerAttendance.work_date >= date_from,
            WorkerAttendance.work_date <= date_to,
            WorkerAttendance.signout_time.isnot(None),  # Only completed shifts
            WorkerAttendance.hours_worked > 0
        )

        # Apply filters
        if project_id:
            query = query.filter(WorkerAttendance.project_id == int(project_id))
        if staff_id:
            query = query.filter(WorkerAttendance.staff_id == int(staff_id))

        records = query.all()

        # Get staff hourly rates for cost calculation
        staff_rates = {}
        for staff in db.query(StaffMember).filter(StaffMember.is_active == True).all():
            hourly_rate = staff.hourly_rate or (staff.daily_rate / 8 if staff.daily_rate else 0)
            staff_rates[staff.id] = {
                'name': staff.full_name,
                'hourly_rate': hourly_rate
            }

        # Process records based on group_by
        grouped_data = {}
        details = []
        unique_projects = set()
        unique_staff = set()
        unique_days = set()

        for att in records:
            staff_info = staff_rates.get(att.staff_id, {'name': 'Unknown', 'hourly_rate': 0})
            hours = att.hours_worked or 0
            cost = hours * staff_info['hourly_rate']

            # Track uniques
            if att.project_name:
                unique_projects.add(att.project_name)
            unique_staff.add(att.staff_id)
            unique_days.add(att.work_date)

            # Build detail record
            details.append({
                'date': att.work_date.isoformat(),
                'staff_id': att.staff_id,
                'staff_name': staff_info['name'],
                'project_id': att.project_id,
                'project_name': att.project_name or 'No Project',
                'task_name': att.task_name,
                'hours': round(hours, 2),
                'cost': round(cost, 2),
                'hourly_rate': staff_info['hourly_rate']
            })

            # Group data
            if group_by == 'project':
                key = att.project_name or 'No Project'
            elif group_by == 'staff':
                key = staff_info['name']
            else:  # day
                key = att.work_date.isoformat()

            if key not in grouped_data:
                grouped_data[key] = {
                    'name': key,
                    'hours': 0,
                    'cost': 0,
                    'staff_ids': set(),
                    'days': set(),
                    'records': []
                }

            grouped_data[key]['hours'] += hours
            grouped_data[key]['cost'] += cost
            grouped_data[key]['staff_ids'].add(att.staff_id)
            grouped_data[key]['days'].add(att.work_date)
            grouped_data[key]['records'].append({
                'staff_name': staff_info['name'],
                'date': att.work_date.isoformat(),
                'hours': round(hours, 2),
                'cost': round(cost, 2)
            })

        # Convert to list and calculate averages
        summary = []
        total_hours = 0
        total_cost = 0

        for key, data in grouped_data.items():
            total_hours += data['hours']
            total_cost += data['cost']
            avg_rate = data['cost'] / data['hours'] if data['hours'] > 0 else 0

            summary.append({
                'name': data['name'],
                'hours': round(data['hours'], 2),
                'cost': round(data['cost'], 2),
                'avg_hourly_rate': round(avg_rate, 2),
                'staff_count': len(data['staff_ids']),
                'days_worked': len(data['days'])
            })

        # Sort by hours descending
        summary.sort(key=lambda x: x['hours'], reverse=True)

        return jsonify({
            'summary': summary,
            'details': details,
            'totals': {
                'hours': round(total_hours, 2),
                'cost': round(total_cost, 2),
                'project_count': len(unique_projects),
                'staff_count': len(unique_staff),
                'day_count': len(unique_days)
            },
            'filters': {
                'date_from': date_from.isoformat(),
                'date_to': date_to.isoformat(),
                'period': period,
                'group_by': group_by
            }
        })

    except Exception as e:
        import traceback
        print(f"Error in productivity API: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/productivity/projects')
@token_required
def get_productivity_projects(current_user):
    """Get list of all projects (from sync_projects and attendance records)"""
    db = SessionLocal()
    try:
        # Get all projects from sync_projects table
        result = db.execute(text('''
            SELECT workpro_id, name
            FROM sync_projects
            WHERE name IS NOT NULL
            ORDER BY name
        ''')).fetchall()

        projects = [{'id': r[0], 'name': r[1]} for r in result if r[0] and r[1]]

        return jsonify({'projects': projects})
    finally:
        db.close()


# ===== RUN SERVER =====

if __name__ == '__main__':
    print("=" * 60)
    print("WAGEPRO - Payroll Management System")
    print("=" * 60)
    print("Starting server at http://localhost:5099")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5099, debug=True)
