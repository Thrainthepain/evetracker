bash python -m venv venv
# Activate venv (source venv/bin/activate or venv\Scripts\activate)
pip install -r requirements.txt

bash python setup_env.py

bash flask db init # Run only ONCE per project
flask db migrate -m "Initial database migration"
flask db upgrade

python run.py