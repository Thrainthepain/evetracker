    # config.py
    # Stores configuration settings for the Flask application.

    import os
    from dotenv import load_dotenv

    # Load environment variables from .env file (optional, useful for development)
    basedir = os.path.abspath(os.path.dirname(__file__))
    load_dotenv(os.path.join(basedir, '.env'))

    class Config:
        """Base configuration settings."""
        # Secret key for session management and security. CHANGE THIS for production!
        SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key-for-dev'

        # Database configuration
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
            'sqlite:///' + os.path.join(basedir, 'app.db') # Default to SQLite in app directory
        SQLALCHEMY_TRACK_MODIFICATIONS = False # Disable modification tracking

        # EVE ESI Application Credentials (Load from environment variables)
        # Get these from https://developers.eveonline.com/
        ESI_CLIENT_ID = os.environ.get('ESI_CLIENT_ID')
        ESI_SECRET_KEY = os.environ.get('ESI_SECRET_KEY')
        ESI_CALLBACK_URL = os.environ.get('ESI_CALLBACK_URL') # e.g., 'http://localhost:5000/sso/callback'

        # ESI Scopes needed by your application
        # Start with a reasonable set and add more as features require them.
        ESI_SCOPES = [
            'publicData', # Always good to include for basic info resolution
            # Character Sheet & Basic Info
            'esi-characters.read_corporation_roles.v1', # View roles in current corp
            'esi-location.read_location.v1', # Current location
            'esi-location.read_online.v1', # Online status indicator
            'esi-location.read_ship_type.v1', # Current ship
            # Wallet
            'esi-wallet.read_character_wallet.v1',
            # Skills
            'esi-skills.read_skillqueue.v1',
            'esi-skills.read_skills.v1',
            # Assets
            'esi-assets.read_assets.v1',
            # Mail
            'esi-mail.read_mail.v1', # Read mail headers
            # Clones (Often useful)
            'esi-clones.read_clones.v1',
            # Contacts (Optional, but common)
            'esi-characters.read_contacts.v1',
            # Notifications (Optional, but common)
            'esi-characters.read_notifications.v1',
            # Corporation Membership (For corp section/audit)
            'esi-corporations.read_corporation_membership.v1',
            # Character Stats (Needed for SP in audit/character page)
            'esi-characters.read_character_stats.v1',
            # Market Orders
            'esi-markets.read_character_orders.v1',
            # Contracts
            'esi-contracts.read_character_contracts.v1',

            # --- Scopes to consider adding later for specific features ---
            # 'esi-corporations.read_structures.v1', # For Corp Structure tracking
            # 'esi-corporations.track_members.v1', # For detailed corp member tracking
            # 'esi-industry.read_character_jobs.v1', # For Industry tracking
            # 'esi-bookmarks.read_character_bookmarks.v1', # For Bookmarks
            # 'esi-calendar.read_calendar_events.v1', # For Calendar
            # 'esi-fittings.read_fittings.v1', # For Fittings
            # Add write scopes (like esi-mail.send_mail.v1) only if absolutely necessary
        ]

        # Site Admin Credentials (Username only - Password hash managed in DB)
        SITE_ADMIN_USERNAME = os.environ.get('SITE_ADMIN_USERNAME') or 'admin'
        # Password hash is stored in the database, not directly in config.
        # The initial admin user/password can be created in run.py if it doesn't exist.

        # --- Key for encrypting refresh tokens ---
        # Generate this ONCE using: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
        # Store it securely in your .env file.
        REFRESH_TOKEN_ENCRYPTION_KEY = os.environ.get('REFRESH_TOKEN_ENCRYPTION_KEY')

        # ESI Base URL
        ESI_BASE_URL = "https://esi.evetech.net/latest"
        EVE_LOGIN_URL = "https://login.eveonline.com"
        EVE_OAUTH_TOKEN_URL = f"{EVE_LOGIN_URL}/v2/oauth/token"
        EVE_OAUTH_AUTHORIZE_URL = f"{EVE_LOGIN_URL}/v2/oauth/authorize/"
        EVE_OAUTH_JWKS_URL = f"{EVE_LOGIN_URL}/oauth/jwks"

        # Application Info (for User-Agent header) - Hardcoded as requested
        APP_NAME = os.environ.get('APP_NAME') or 'Eve Tracker'
        APP_VERSION = os.environ.get('APP_VERSION') or '1.0.0'
        APP_CONTACT_EMAIL = os.environ.get('APP_CONTACT_EMAIL') or 'thrainkrill@gmail.com'

    