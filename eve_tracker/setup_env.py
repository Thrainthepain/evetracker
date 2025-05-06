    # setup_env.py
    # Interactive script to create the initial .env file for configuration.

    import os
    import secrets
    from cryptography.fernet import Fernet
    import sys
    from urllib.parse import urlunsplit
    import datetime # Import datetime

    ENV_FILE = '.env'
    EXAMPLE_FILE = '.env.example' # Assumes you have this template

    def prompt_user(prompt_text, default=None, required=False):
        """Prompts user for input with an optional default value and required flag."""
        while True:
            prompt_full = prompt_text
            if default:
                prompt_full += f" [{default}]"
            prompt_full += ": "
            value = input(prompt_full).strip()
            if value:
                return value
            elif default is not None: # Check default after checking for value
                return default
            elif required:
                print("This field is required. Please enter a value.")
            else: # Not required, no default, no value -> return empty string or None? Let's return empty.
                return ""


    def generate_secret_key(length=24):
        """Generates a secure random hex key."""
        return secrets.token_hex(length)

    def generate_fernet_key():
        """Generates a Fernet key for encryption."""
        return Fernet.generate_key().decode()

    def create_env_file():
        """Interactively creates the .env file."""
        print("-" * 30)
        print("EVE Tracker Backend Setup")
        print("-" * 30)
        print(f"This script will help you create the '{ENV_FILE}' configuration file.")

        if os.path.exists(ENV_FILE):
            overwrite = input(f"'{ENV_FILE}' already exists. Overwrite? (y/N): ").strip().lower()
            if overwrite != 'y':
                print("Setup aborted. Please manually edit the existing .env file.")
                sys.exit(0)
            else:
                print(f"Overwriting existing '{ENV_FILE}'...")

        print("\n--- ESI Application Details ---")
        print("Get these from https://developers.eveonline.com/")
        esi_client_id = prompt_user("Enter ESI Client ID", required=True)
        esi_secret_key = prompt_user("Enter ESI Secret Key", required=True)

        print("\n--- Site URL Configuration ---")
        print("Enter the details for the URL where this application will be hosted.")
        protocol = prompt_user("Protocol (http or https)", "http")
        domain = prompt_user("Main Domain Name (e.g., example.com)", required=True)
        subdomain = prompt_user("Subdomain (leave blank if none)")
        port_str = prompt_user("Port (leave blank for default http=80, https=443)", "")

        # Construct hostname
        hostname = f"{subdomain}.{domain}" if subdomain else domain

        # Construct netloc (hostname:port)
        netloc = hostname
        port = None
        if port_str:
            try:
                port = int(port_str)
                # Only include port if it's not the default for the protocol
                if not ((protocol == 'http' and port == 80) or (protocol == 'https' and port == 443)):
                    netloc = f"{hostname}:{port}"
            except ValueError:
                print(f"Warning: Invalid port '{port_str}'. Using default port.")

        # Construct the base URL and the static callback URL
        base_url = urlunsplit((protocol, netloc, '', '', '')) # scheme, netloc, path, query, fragment
        static_callback_path = "/sso/callback" # Static path
        esi_callback_url = base_url.strip('/') + static_callback_path
        print(f"\nConstructed ESI Callback URL: {esi_callback_url}")
        print("IMPORTANT: Ensure this EXACT URL is registered as the Callback URL in your ESI application settings!")


        # --- Use Hardcoded Application Info ---
        app_name = "Eve Tracker"
        app_version = "1.0.0"
        app_contact_email = "thrainkrill@gmail.com"
        print("\n--- Application Info (Hardcoded) ---")
        print(f"App Name: {app_name}")
        print(f"App Version: {app_version}")
        print(f"Contact Email: {app_contact_email}")
        # --- End Hardcoded Application Info ---


        print("\n--- Generating Secrets ---")
        flask_secret_key = generate_secret_key()
        encryption_key = generate_fernet_key()
        print("Generated Flask SECRET_KEY.")
        print("Generated REFRESH_TOKEN_ENCRYPTION_KEY.")

        print(f"\nWriting configuration to '{ENV_FILE}'...")

        # Default values that usually don't need prompting for basic setup
        flask_debug = '1' # Enable debug for initial setup/dev
        # Default to SQLite, user can change later if needed
        database_url = f"sqlite:///{os.path.join(os.path.abspath(os.path.dirname(__file__)), 'app.db')}"
        site_admin_username = 'admin'

        env_content = f"""# .env - Generated by setup_env.py {datetime.datetime.now()}
# --- Flask Settings ---
SECRET_KEY='{flask_secret_key}'
FLASK_DEBUG={flask_debug}
# FLASK_ENV=development # Optional: Can be set explicitly

# --- Database URL ---
# Defaulting to SQLite. Change if using PostgreSQL, MySQL, etc.
DATABASE_URL='{database_url}'

# --- EVE ESI Application Credentials ---
ESI_CLIENT_ID='{esi_client_id}'
ESI_SECRET_KEY='{esi_secret_key}'
ESI_CALLBACK_URL='{esi_callback_url}'

# --- Site Admin Credentials ---
# Username for the local site administrator account
SITE_ADMIN_USERNAME='{site_admin_username}'
# Initial password ('changeme') is handled by run.py if user doesn't exist

# --- Cryptography Key ---
# Used for encrypting EVE refresh tokens stored in the database. KEEP THIS SECRET!
REFRESH_TOKEN_ENCRYPTION_KEY='{encryption_key}'

# --- Application Info (User-Agent) ---
APP_NAME='{app_name}'
APP_VERSION='{app_version}'
APP_CONTACT_EMAIL='{app_contact_email}'
"""

        try:
            with open(ENV_FILE, 'w') as f:
                f.write(env_content)
            print(f"\nSuccessfully created '{ENV_FILE}'.")
            print("\n--- Next Steps ---")
            print("1. Review the generated .env file (especially DATABASE_URL if not using SQLite).")
            print("2. Initialize/Upgrade the database (if needed):")
            print("   flask db init  (run only once ever for this project)")
            print("   flask db migrate -m \"Initial setup\"")
            print("   flask db upgrade")
            print("3. Start the application:")
            print("   python run.py")
            print("4. Log in as Site Admin (user: 'admin', pass: 'changeme') and change the password immediately via the application's admin interface (once implemented).")
            print("-" * 30)

        except IOError as e:
            print(f"\nError writing to '{ENV_FILE}': {e}", file=sys.stderr)
            print("Please check file permissions.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
            sys.exit(1)


    if __name__ == "__main__":
        # Add datetime import for generated timestamp
        import datetime
        create_env_file()
    