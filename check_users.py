from app import app, db, User

with app.app_context():
    users = User.query.all()
    print(f"Total users: {len(users)}")
    for user in users:
        print(f"User: {user.email}, Username: {user.username}, Active: {user.active}, Authenticated: {user.authenticated}")
