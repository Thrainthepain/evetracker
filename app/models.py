    # app/models.py
    # Defines the database structure using SQLAlchemy models.

    from app import db # Import the db instance from app/__init__.py
    import datetime
    # Import password hashing utilities
    from werkzeug.security import generate_password_hash, check_password_hash
    # Import utils for potential direct use (though routes usually call utils)
    # from app import utils

    class User(db.Model):
        """ Model for Site Administrators (non-EVE users) """
        __tablename__ = 'users' # Optional: Define table name explicitly

        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, index=True, nullable=False)
        password_hash = db.Column(db.String(128), nullable=False) # Store hash, not plain text!
        is_active = db.Column(db.Boolean, default=True)
        created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

        # --- Password Hashing Methods ---
        def set_password(self, password):
            """Hashes the password and stores it."""
            # Increased default iterations for better security if possible
            self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

        def check_password(self, password):
            """Checks if the provided password matches the stored hash."""
            if not self.password_hash: # Handle case where hash might be missing
                return False
            return check_password_hash(self.password_hash, password)
        # --- End Password Hashing Methods ---

        def __repr__(self):
            return f'<User {self.username}>'

    class EveCharacter(db.Model):
        """ Model to store EVE Character info and tokens """
        __tablename__ = 'eve_characters'

        id = db.Column(db.Integer, primary_key=True) # EVE Character ID (use BigInteger if needed)
        name = db.Column(db.String(100), index=True, nullable=False)
        corporation_id = db.Column(db.Integer, index=True, nullable=True) # Nullable if char has no corp?
        alliance_id = db.Column(db.Integer, index=True, nullable=True)
        owner_hash = db.Column(db.String(255), nullable=True) # From verified token payload

        # Store encrypted refresh token securely! Use the 'cryptography' library.
        # Using LargeBinary to store the encrypted bytes directly.
        encrypted_refresh_token = db.Column(db.LargeBinary, nullable=True)
        scopes = db.Column(db.Text, nullable=True) # Store granted scopes as space-separated string or JSON
        token_last_validated = db.Column(db.DateTime, nullable=True) # When scopes/token were last confirmed valid
        # token_expires = db.Column(db.DateTime) # Expiry of the *access* token (less critical to store)

        # Potential relationship to a local user account if needed
        # user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
        # user = db.relationship('User', backref=db.backref('eve_characters', lazy=True))

        created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        last_updated = db.Column(db.DateTime, onupdate=datetime.datetime.utcnow, default=datetime.datetime.utcnow) # Track ESI data updates


        def __repr__(self):
            return f'<EveCharacter {self.name} ({self.id})>'

    # --- Add other models as needed ---

    class BuybackRequest(db.Model):
        """ Model for Buyback Program Requests """
        __tablename__ = 'buyback_requests'

        id = db.Column(db.Integer, primary_key=True)
        tracking_code = db.Column(db.String(20), unique=True, index=True, nullable=False)
        eve_character_id = db.Column(db.Integer, db.ForeignKey('eve_characters.id'), nullable=False, index=True)
        submitted_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)
        raw_items_input = db.Column(db.Text) # Store the user's pasted input
        calculated_value = db.Column(db.Float) # Store estimated value at time of submission
        status = db.Column(db.String(50), default='Pending Submission', index=True) # e.g., Pending Submission, Pending Contract, Accepted, Rejected, Completed, Deleted
        contract_id = db.Column(db.BigInteger, nullable=True, index=True) # Link to in-game contract
        notes = db.Column(db.Text, nullable=True) # Admin notes or system messages
        last_checked = db.Column(db.DateTime) # When ESI was last checked for contract status

        character = db.relationship('EveCharacter', backref=db.backref('buyback_requests', lazy='dynamic'))

        def __repr__(self):
            return f'<BuybackRequest {self.tracking_code} ({self.status})>'

    # Example: Model for storing fetched Assets (simplified)
    # class Asset(db.Model):
    #     __tablename__ = 'assets'
    #     item_id = db.Column(db.BigInteger, primary_key=True) # ESI item_id (unique per item instance)
    #     type_id = db.Column(db.Integer, nullable=False, index=True)
    #     location_id = db.Column(db.BigInteger, nullable=False, index=True)
    #     location_flag = db.Column(db.String(50), nullable=False)
    #     quantity = db.Column(db.Integer, nullable=False)
    #     is_singleton = db.Column(db.Boolean, nullable=False)
    #     owner_char_id = db.Column(db.Integer, db.ForeignKey('eve_characters.id'), nullable=False, index=True)
    #     last_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    #
    #     owner = db.relationship('EveCharacter', backref=db.backref('assets', lazy='dynamic'))


    # Add models for Wallet Journal, Skills, Corp Info, External Apps config, Roles etc.
    