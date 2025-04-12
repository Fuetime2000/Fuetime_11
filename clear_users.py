from app import app, db, User

def clear_users():
    try:
        # Delete all users except admin
        User.query.filter(User.is_admin == False).delete()
        db.session.commit()
        print("Successfully cleared all non-admin users from the database")
    except Exception as e:
        db.session.rollback()
        print(f"Error clearing users: {str(e)}")

if __name__ == '__main__':
    with app.app_context():
        clear_users()
