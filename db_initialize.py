from project import create_app, db, models

def initialize_database():
    app = create_app()
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    initialize_database()
