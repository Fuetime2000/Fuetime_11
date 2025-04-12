import os
from app import app, db, User
from werkzeug.security import generate_password_hash
from datetime import datetime

# Get absolute path to database file
db_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fuetime.db')

# Delete existing database file
if os.path.exists(db_file):
    os.remove(db_file)
    print(f"Removed existing database: {db_file}")

def init_database():
    with app.app_context():
        # Create all tables
        db.create_all()
        
        try:
            # Create admin user with all required fields
            admin = User()
            admin.email = 'admin@example.com'
            admin.phone = '1234567890'
            admin.full_name = 'Admin User'
            admin.username = 'admin'  # Set a fixed username for admin
            admin.password_hash = generate_password_hash('admin123')
            admin.is_admin = True
            admin.work = 'Administrator'
            admin.experience = '5+ years'
            admin.education = 'Bachelor\'s Degree'
            admin.live_location = 'Main Office'
            admin.current_location = 'Main Office'
            admin.payment_type = 'Hourly'
            admin.payment_charge = 0.0
            admin.skills = 'Administration, Management'
            admin.categories = 'Administration'
            admin.is_online = False
            admin.last_active = datetime.utcnow()
            
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully")
            
        except Exception as e:
            print(f"Error creating admin user: {e}")
            db.session.rollback()
        
        print("Database initialized successfully")

if __name__ == "__main__":
    init_database()
