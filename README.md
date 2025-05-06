# EVE Tracker Backend - Setup Guide

This document provides instructions for setting up and running the EVE Tracker backend application built with Python and Flask.

## Prerequisites

Before you begin, ensure you have the following installed on your system:

1.  **Python:** Version 3.8 or higher is recommended. You can download it from [python.org](https://www.python.org/). Verify installation by running `python --version` or `python3 --version` in your terminal.
2.  **pip:** Python's package installer. It usually comes with Python. Verify installation by running `pip --version` or `pip3 --version`.
3.  **Git:** (Optional) If you are cloning the repository from a version control system like GitHub. Download from [git-scm.com](https://git-scm.com/).
4.  **(For Production/Non-SQLite Database):** A database server like [PostgreSQL](https://www.postgresql.org/download/) or [MySQL](https://dev.mysql.com/downloads/mysql/)/[MariaDB](https://mariadb.org/download/). SQLite is used by default for development and requires no separate installation.
5.  **(For Production):** A production web server like [Nginx](https://nginx.org/en/download.html) or [Apache](https://httpd.apache.org/download.cgi).

## Setup Steps

1.  **Get the Code:**
    * If using Git, clone the repository:
        ```bash
        git clone <repository_url>
        cd <repository_directory>
        ```
    * Otherwise, ensure all the project files (`run.py`, `config.py`, `setup_env.py`, `requirements.txt`, and the `app/` directory with its contents) are placed in a single project folder.

2.  **Create and Activate Virtual Environment:**
    * It's highly recommended to use a virtual environment to manage dependencies. Navigate to your project folder in the terminal and run:
        ```bash
        # Create the virtual environment (named 'venv')
        python -m venv venv

        # Activate the virtual environment
        # On Windows:
        # venv\Scripts\activate
        # On macOS/Linux:
        # source venv/bin/activate
        ```
    * You should see `(venv)` prefixed to your terminal prompt, indicating the environment is active.

3.  **Install Dependencies:**
    * While the virtual environment is active, install the required Python packages:
        ```bash
        pip install -r requirements.txt
        ```

4.  **Run Interactive Setup Script:**
    * This script will guide you through creating the essential `.env` configuration file. Run:
        ```bash
        python setup_env.py
        ```
    * **Follow the prompts:**
        * Enter your **ESI Client ID** and **Secret Key** from your application registered at [https://developers.eveonline.com/](https://developers.eveonline.com/).
        * Enter the **URL components** (protocol, domain, subdomain, port) where your application will be hosted. The script will construct the `ESI_CALLBACK_URL` (e.g., `http://yourdomain.com/sso/callback`) based on your input.
        * **Crucially:** Ensure the constructed `ESI_CALLBACK_URL` **exactly matches** the one registered in your ESI application settings on the EVE Developers site.
    * The script uses hardcoded application info (`Eve Tracker`, `1.0.0`, `thrainkrill@gmail.com`) for the User-Agent header.
    * It will automatically generate the `SECRET_KEY` for Flask and the `REFRESH_TOKEN_ENCRYPTION_KEY` for securing EVE refresh tokens.
    * It will create the `.env` file in your project directory.

5.  **Review `.env` File:**
    * Open the newly created `.env` file.
    * Verify the `ESI_CALLBACK_URL` is correct.
    * **Database:** By default, it's configured for SQLite (`DATABASE_URL='sqlite:///app.db'`). If you installed and configured a different database (like PostgreSQL) for production, update the `DATABASE_URL` here with your connection string (e.g., `postgresql://user:password@host:port/database_name`).
    * Keep the generated keys secret! Ensure `.env` is listed in your `.gitignore` file if using Git.

6.  **Database Initialization/Migration:**
    * **First time setup (using Flask-Migrate):** If this is the very first time setting up the database for this project and you want to use migrations for future schema changes (recommended):
        ```bash
        # Initialize the migration repository (run only ONCE per project)
        flask db init

        # Create the initial migration script based on models.py
        flask db migrate -m "Initial database setup."

        # Apply the migration to create the database tables
        flask db upgrade
        ```
    * **If NOT using Flask-Migrate (or for simple SQLite setup):** The `run.py` script includes `db.create_all()`, which will attempt to create tables based on your models if they don't exist when the app starts. This is less flexible for future changes than using migrations.
    * **Subsequent Schema Changes:** If you modify `app/models.py` later, create a new migration:
        ```bash
        flask db migrate -m "Description of changes."
        flask db upgrade
        ```

7.  **Run the Development Server:**
    * You can now start the Flask development server:
        ```bash
        python run.py
        ```
    * The server will typically start on `http://127.0.0.1:5000/` or `http://0.0.0.0:5000/`.
    * The first time it runs successfully after database setup, it should create the default site admin user (`admin` / `changeme`).
    * Access the application through your web browser. You should see the backend status page or your integrated frontend.

8.  **Initial Site Admin Login:**
    * Navigate to the Site Admin Login section/page in the application.
    * Log in using:
        * Username: `admin` (or the value of `SITE_ADMIN_USERNAME` in `.env`)
        * Password: `changeme`
    * **IMPORTANT:** You *must* implement a feature within the Admin Panel to allow the site admin to change this default password immediately after the first login.

## Production Deployment

The Flask development server (`python run.py`) is **NOT suitable for production**. For deployment, you need:

1.  **Database Server:**
    * Ensure a robust database server (like PostgreSQL) is installed, configured, secured, and running on your production server.
    * Update the `DATABASE_URL` in your production `.env` file accordingly.
2.  **WSGI Server (Gunicorn):**
    * Gunicorn is installed via `requirements.txt`. You need to run your Flask app using Gunicorn instead of the development server. A common command looks like:
        ```bash
        # Example: Run Gunicorn with 4 worker processes, binding to localhost port 8000
        # Ensure 'app:create_app()' points to your application factory correctly
        # The callable might be 'run:app' if 'app = create_app()' is directly in run.py
        gunicorn -w 4 -b 127.0.0.1:8000 'run:app'
        ```
    * You'll typically want to run Gunicorn as a system service (e.g., using `systemd`) so it starts automatically and restarts if it crashes. See the [Gunicorn documentation](https://docs.gunicorn.org/en/stable/deploy.html).
3.  **Web Server / Reverse Proxy (Nginx/Apache):**
    * Install Nginx or Apache on your server using your OS package manager.
    * Configure it as a reverse proxy to:
        * Receive incoming HTTP/HTTPS requests from users.
        * Forward requests for your application to the Gunicorn process (e.g., listening on `127.0.0.1:8000`).
        * Handle SSL/TLS termination (HTTPS).
        * Serve static files directly (more efficient than Flask serving them).
        * Optionally handle load balancing, rate limiting, etc.
    * See example configurations in the [Flask Deployment Documentation](https://flask.palletsprojects.com/en/latest/deploying/) and the documentation for [Nginx](https://nginx.org/en/docs/) or [Apache](https://httpd.apache.org/docs/).

Setting up the production environment requires system administration knowledge specific to your chosen server OS and software.


bash python -m venv venv
# Activate venv (source venv/bin/activate or venv\Scripts\activate)
pip install -r requirements.txt

bash python setup_env.py

bash flask db init # Run only ONCE per project
flask db migrate -m "Initial database migration"
flask db upgrade

python run.py
