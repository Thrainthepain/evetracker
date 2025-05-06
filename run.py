    # run.py
    # Main entry point to start the Flask development server.

    import os
    import sys

    # Attempt to load environment variables early to check essential config
    from dotenv import load_dotenv
    load_dotenv()

    # --- Configuration Check ---
    # Check if essential variables are loaded from .env or environment
    required_vars = ['ESI_CLIENT_ID', 'ESI_SECRET_KEY', 'ESI_CALLBACK_URL', 'REFRESH_TOKEN_ENCRYPTION_KEY', 'SECRET_KEY']
    missing_vars = [var for var in required_vars if not os.environ.get(var)]

    if missing_vars:
        print("="*50, file=sys.stderr)
        print("ERROR: Missing essential configuration variables!", file=sys.stderr)
        print("The following variables are not set in your environment or .env file:", file=sys.stderr)
        for var in missing_vars:
            print(f"  - {var}", file=sys.stderr)
        print("\nPlease run the setup script to generate the .env file:", file=sys.stderr)
        print("  python setup_env.py", file=sys.stderr)
        print("="*50, file=sys.stderr)
        sys.exit(1) # Exit if configuration is missing
    # --- End Configuration Check ---


    from app import create_app, db # Import factory and db instance AFTER check
    from app.models import User, EveCharacter # Import models
    # from flask_migrate import Migrate # Import Migrate if using migrations

    # Create the Flask app instance using the factory
    # Config is loaded inside create_app via Config class which uses os.environ.get
    app = create_app()
    # migrate = Migrate(app, db) # Initialize Migrate here if not done in factory

    # Optional: Add Flask shell context processors to make db and models available in `flask shell`
    @app.shell_context_processor
    def make_shell_context():
        return {'db': db, 'User': User, 'EveCharacter': EveCharacter}

    def create_initial_admin():
        """Creates the initial site admin user if none exists."""
        with app.app_context():
            admin_username = app.config.get('SITE_ADMIN_USERNAME', 'admin')
            # Check if the admin user already exists
            if not User.query.filter_by(username=admin_username).first():
                app.logger.info(f"Creating initial site admin user: {admin_username}")
                # Use 'changeme' as the default password for the initial setup
                default_password = 'changeme'
                admin_user = User(username=admin_username)
                admin_user.set_password(default_password) # Hash the password
                db.session.add(admin_user)
                try:
                    db.session.commit()
                    app.logger.info(f"Default site admin '{admin_username}' created with temporary password.")
                    app.logger.warning("IMPORTANT: Log in as this user and change the password immediately!")
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f"Error creating initial admin user: {e}")
            else:
                 app.logger.debug(f"Site admin user '{admin_username}' already exists.")


    if __name__ == '__main__':
        # Create database tables if they don't exist (useful for SQLite in development)
        with app.app_context():
            app.logger.info("Ensuring database tables exist...")
            # Use Flask-Migrate for production/complex changes:
            # flask db upgrade
            # For simple dev setups or initial creation, db.create_all() is okay.
            try:
                 # Check if migrations are set up, otherwise use create_all
                 migration_dir = os.path.join(os.path.dirname(__file__), 'migrations')
                 if not os.path.exists(migration_dir):
                     app.logger.info("Migrations directory not found, using db.create_all(). Run 'flask db init' for migrations.")
                     db.create_all()
                 else:
                     app.logger.info("Migrations directory found. Use 'flask db upgrade' to apply migrations.")
                     # You might still run create_all() as a fallback if upgrade fails/isn't run
                     # db.create_all() # Optional fallback
            except Exception as e:
                app.logger.error(f"Error during database setup: {e}")
            app.logger.info("Database tables should exist now.")

            # Attempt to create the initial admin user
            create_initial_admin()


        # Run the Flask development server
        # Debug mode should be OFF in production!
        app.logger.info("Starting Flask development server...")
        # Use host='0.0.0.0' to make it accessible on your network
        # Use port 5000 by default unless specified otherwise
        port = int(os.environ.get('PORT', 5000))
        # Turn off reloader if causing issues with cache/globals in dev, but debug=True is useful
        app.run(debug=True, host='0.0.0.0', port=port, use_reloader=False)

    