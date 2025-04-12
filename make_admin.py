from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Create all tables
    db.create_all()
    
    # Check if admin user exists
    admin = User.query.filter_by(email='admin@example.com').first()
    if not admin:
        # Create admin user
        admin = User(
            email='admin@example.com',
            phone='1234567890',
            full_name='Admin User',
            is_admin=True
        )
        admin.password_hash = generate_password_hash('admin123')
        db.session.add(admin)
        db.session.commit()
        print(f'Created admin user with email: {admin.email} and password: admin123')
    else:
        # Make existing user admin
        admin.is_admin = True
        db.session.commit()
        print(f'Updated {admin.email} to admin')
