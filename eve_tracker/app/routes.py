# app/routes.py
# Contains the main routes for the application using Flask Blueprints.

import base64
import datetime
import requests # Still needed for token exchange/revocation directly
import jwt # For specific exceptions
import os # For state generation
import threading # For cache lock in utils
from flask import (
    Blueprint, request, redirect, session, jsonify, render_template, url_for, current_app, flash
)
# Import db instance and models for database interaction
from app import db
from app.models import User, EveCharacter
# Import helper functions from utils
from app.utils import (
    encrypt_token, decrypt_token, get_esi_access_token, esi_request, verify_esi_jwt,
    resolve_ids_to_names # Import the name resolution helper
)


# Create a Blueprint instance
bp = Blueprint('main', __name__)


# --- Main Routes ---

@bp.route('/')
def index():
    """ Renders the main frontend HTML page. """
    # Flask will look for 'index.html' inside the 'templates' folder
    # located within the 'app' directory by default.
    return render_template('index.html')

# --- EVE SSO Authentication Routes ---

@bp.route('/login/eve')
def login_eve():
    """ Redirects the user to the EVE SSO authorization page. """
    state = base64.urlsafe_b64encode(os.urandom(16)).decode() # Example secure state
    session['oauth_state'] = state

    scopes = ' '.join(current_app.config['ESI_SCOPES'])
    sso_url = (
        f"{current_app.config['EVE_OAUTH_AUTHORIZE_URL']}?"
        f"response_type=code"
        f"&redirect_uri={current_app.config['ESI_CALLBACK_URL']}"
        f"&client_id={current_app.config['ESI_CLIENT_ID']}"
        f"&scope={scopes}"
        f"&state={state}"
    )
    current_app.logger.info(f"Redirecting to EVE SSO for authorization.")
    return redirect(sso_url)

# Renamed route to match setup script and common practice
@bp.route('/sso/callback')
def callback():
    """ Handles the callback from EVE SSO. """
    auth_code = request.args.get('code')
    returned_state = request.args.get('state')

    # --- STATE VALIDATION ---
    stored_state = session.pop('oauth_state', None)
    if not returned_state or returned_state != stored_state:
        flash('Invalid state parameter. Authentication failed. Please try logging in again.', 'danger')
        current_app.logger.warning("EVE Callback: State mismatch.")
        return redirect(url_for('main.index'))
    # --- END STATE VALIDATION ---

    if not auth_code:
        flash('Authentication failed: No authorization code received from EVE Online.', 'danger')
        current_app.logger.warning("EVE Callback: No authorization code received.")
        return redirect(url_for('main.index'))

    # --- TOKEN EXCHANGE ---
    token_url = current_app.config['EVE_OAUTH_TOKEN_URL']
    client_id = current_app.config['ESI_CLIENT_ID']
    client_secret = current_app.config['ESI_SECRET_KEY']

    # Prepare Basic Auth header
    auth_str = f"{client_id}:{client_secret}"
    auth_bytes = auth_str.encode('utf-8')
    auth_b64 = base64.b64encode(auth_bytes).decode('utf-8')

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Host': 'login.eveonline.com',
        'Authorization': f'Basic {auth_b64}'
    }
    data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
         # Explicitly add redirect_uri for code exchange if needed by provider
         # 'redirect_uri': current_app.config['ESI_CALLBACK_URL']
    }

    access_token = None
    refresh_token = None
    expires_in = None

    try:
        current_app.logger.info("Exchanging EVE authorization code for tokens.")
        response = requests.post(token_url, headers=headers, data=data, timeout=15)
        response.raise_for_status() # Raise exception for bad status codes
        token_data = response.json()
        access_token = token_data['access_token']
        refresh_token = token_data['refresh_token'] # This is the crucial one to store
        expires_in = token_data['expires_in']
        current_app.logger.info("Token exchange successful.")
    except requests.exceptions.HTTPError as e:
         error_details = e.response.text[:200]
         flash(f'Token exchange failed with EVE Online ({e.response.status_code}). Please try again.', 'danger')
         current_app.logger.error(f"EVE Callback: Token exchange HTTPError {e.response.status_code} - {error_details} - {e}")
         return redirect(url_for('main.index'))
    except requests.exceptions.RequestException as e:
        flash(f'Token exchange failed: Network error connecting to EVE Online.', 'danger')
        current_app.logger.error(f"EVE Callback: Token exchange RequestException - {e}")
        return redirect(url_for('main.index'))
    except Exception as e:
         flash(f'Token exchange failed: An unexpected error occurred.', 'danger')
         current_app.logger.error(f"EVE Callback: Token exchange unexpected error - {e}", exc_info=True)
         return redirect(url_for('main.index'))
    # --- END TOKEN EXCHANGE ---

    # --- TOKEN VERIFICATION ---
    try:
        current_app.logger.info("Verifying received EVE access token (JWT).")
        payload = verify_esi_jwt(access_token) # Use helper from utils
        character_id = int(payload['sub'].split(':')[-1]) # Extract ID from 'sub' claim
        character_name = payload['name']
        scopes_granted_list = payload.get('scp', []) # Scopes claim
        if isinstance(scopes_granted_list, str): # Handle if scopes are space-separated string
            scopes_granted_list = scopes_granted_list.split(' ')
        owner_hash = payload['owner']
        current_app.logger.info(f"Token verified for Character ID: {character_id}, Name: {character_name}")

    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, Exception) as e:
        flash(f'Received token verification failed: {e}. Please try logging in again.', 'danger')
        current_app.logger.error(f"EVE Callback: Token verification failed - {e}")
        return redirect(url_for('main.index'))
    # --- END TOKEN VERIFICATION ---

    # --- DATABASE UPDATE ---
    encrypted_refresh_token_bytes = encrypt_token(refresh_token) # Use helper
    if not encrypted_refresh_token_bytes:
         flash(f'Critical error: Failed to encrypt refresh token. Cannot complete login.', 'danger')
         current_app.logger.error(f"EVE Callback: Failed to encrypt refresh token for char {character_id}. Check REFRESH_TOKEN_ENCRYPTION_KEY.")
         return redirect(url_for('main.index'))


    character = EveCharacter.query.get(character_id)
    if not character:
        character = EveCharacter(id=character_id)
        db.session.add(character)
        current_app.logger.info(f"Creating new EveCharacter record for ID: {character_id}")

    character.name = character_name
    character.owner_hash = owner_hash
    character.scopes = ' '.join(scopes_granted_list) # Store as space-separated string
    character.encrypted_refresh_token = encrypted_refresh_token_bytes # Store encrypted bytes
    character.token_last_validated = datetime.datetime.utcnow() # Mark as validated now

    try:
        db.session.commit()
        current_app.logger.info(f"Database updated successfully for char {character_id}.")
    except Exception as e:
        db.session.rollback()
        flash(f'Database error saving login information. Please try again.', 'danger')
        current_app.logger.error(f"EVE Callback: DB commit failed for char {character_id} - {e}", exc_info=True)
        return redirect(url_for('main.index'))
    # --- END DATABASE UPDATE ---

    # --- ROLE ASSIGNMENT ---
    user_roles = ['member'] # Default role
    try:
        # Fetch roles from ESI using the newly acquired token
        # Use v2 for roles endpoint
        roles_data = esi_request(f"/characters/{character_id}/roles/", character_id=character_id, version='v2')
        if isinstance(roles_data, dict) and 'roles' in roles_data:
             esi_roles = roles_data['roles']
             current_app.logger.info(f"Fetched ESI roles for {character_id}: {esi_roles}")
             # Example logic: Assign 'admin' role if Director, 'recruiter' if Personnel Manager
             if 'Director' in esi_roles:
                  user_roles.append('admin') # Grant 'admin' role for EVE Directors
             if 'Personnel_Manager' in esi_roles:
                  user_roles.append('recruiter') # Grant 'recruiter' role
             # Add other role logic as needed (e.g., based on titles?)
             # titles_data = esi_request(f"/characters/{character_id}/titles/", character_id=character_id)

        elif isinstance(roles_data, dict) and 'error' in roles_data:
             current_app.logger.warning(f"Could not fetch ESI roles for {character_id}: {roles_data['error']}")
        else:
             current_app.logger.warning(f"Unexpected response when fetching ESI roles for {character_id}: {roles_data}")

    except Exception as e:
         current_app.logger.error(f"Error fetching/processing ESI roles for {character_id}: {e}", exc_info=True)
    # --- END ROLE ASSIGNMENT ---

    # --- SESSION CREATION ---
    session.clear() # Clear any old session data
    session['eve_character_id'] = character_id
    session['eve_character_name'] = character_name
    session['eve_roles'] = list(set(user_roles)) # Store unique roles
    session['eve_logged_in'] = True
    current_app.logger.info(f"EVE User Session created for {character_name} ({character_id}) with roles: {session['eve_roles']}")
    # --- END SESSION CREATION ---

    flash(f'Successfully logged in via EVE Online as: {character_name}', 'success')
    return redirect(url_for('main.index')) # Redirect to frontend dashboard

@bp.route('/logout/eve')
def logout_eve():
    """ Clears the EVE user session and attempts to revoke the refresh token. """
    character_id = session.get('eve_character_id')
    character_name = session.get('eve_character_name', 'Unknown EVE User')

    # --- Token Revocation ---
    if character_id:
        current_app.logger.info(f"Attempting token revocation for EVE User {character_name} ({character_id})")
        character = EveCharacter.query.get(character_id)
        if character and character.encrypted_refresh_token:
            decrypted_token = decrypt_token(character.encrypted_refresh_token)
            if decrypted_token:
                revoke_url = f"{current_app.config['EVE_LOGIN_URL']}/v2/oauth/revoke"
                client_id = current_app.config['ESI_CLIENT_ID']
                client_secret = current_app.config['ESI_SECRET_KEY']

                # Prepare Basic Auth header
                auth_str = f"{client_id}:{client_secret}"
                auth_b64 = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
                headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': f'Basic {auth_b64}', 'Host': 'login.eveonline.com'}
                data = {'token_type_hint': 'refresh_token', 'token': decrypted_token}

                try:
                    response = requests.post(revoke_url, headers=headers, data=data, timeout=10)
                    if response.status_code == 200:
                         current_app.logger.info(f"Successfully revoked token for char {character_id}")
                         # Optionally clear the stored token from DB after successful revocation
                         # character.encrypted_refresh_token = None
                         # db.session.commit()
                    else:
                         # Log non-200 responses, but don't block logout
                         current_app.logger.warning(f"Token revocation for {character_id} returned status {response.status_code}: {response.text[:100]}")
                except requests.exceptions.RequestException as e:
                     # Log network or other request errors, but don't block logout
                     current_app.logger.error(f"Error during token revocation request for {character_id}: {e}")
                except Exception as e:
                    current_app.logger.error(f"Unexpected error during token revocation for {character_id}: {e}", exc_info=True)

            else:
                 current_app.logger.error(f"Could not decrypt refresh token for revocation for char {character_id}")
        else:
             current_app.logger.warning(f"No character or encrypted refresh token found in DB for char {character_id} during logout.")
    # --- End Token Revocation ---

    # --- Clear Session ---
    # This happens regardless of revocation success/failure
    current_app.logger.info(f"Clearing session for EVE User {character_name} ({character_id})")
    session.pop('eve_character_id', None)
    session.pop('eve_character_name', None)
    session.pop('eve_roles', None)
    session.pop('eve_logged_in', None)
    flash(f'{character_name} logged out.', 'info')
    # --- End Clear Session ---

    return redirect(url_for('main.index'))

# --- Site Admin Authentication Routes ---

@bp.route('/login/admin', methods=['POST'])
def login_admin():
    """ Handles username/password login for site admins. """
    username = request.form.get('admin-username')
    password = request.form.get('admin-password')

    if not username or not password:
        flash('Username and password required.', 'warning')
        return redirect(url_for('main.index') + '#admin-login')

    # --- DATABASE LOOKUP AND PASSWORD CHECK ---
    admin_user = User.query.filter_by(username=username, is_active=True).first() # Check if active

    if admin_user and admin_user.check_password(password):
        # Password matches
        session.clear() # Clear any existing session (like EVE user)
        session['site_admin_logged_in'] = True
        session['site_admin_username'] = admin_user.username
        current_app.logger.info(f"Site Admin '{admin_user.username}' logged in successfully.")
        flash('Site Admin login successful.', 'success')
        # Redirect to the frontend, hash determines the view
        return redirect(url_for('main.index') + '#admin')
    else:
        # Invalid username or password
        current_app.logger.warning(f"Failed Site Admin login attempt for username: {username}")
        flash('Invalid site admin username or password.', 'danger')
        return redirect(url_for('main.index') + '#admin-login')
    # --- END DATABASE LOOKUP ---


@bp.route('/logout/admin')
def logout_admin():
    """ Clears the site admin session. """
    username = session.get('site_admin_username', 'Unknown Admin')
    session.pop('site_admin_logged_in', None)
    session.pop('site_admin_username', None)
    current_app.logger.info(f"Site Admin '{username}' logged out.")
    flash('Site Admin logged out.', 'info')
    return redirect(url_for('main.index'))


# --- API Endpoints ---

@bp.route('/api/status')
def api_status():
    """ Simple endpoint to check login status for frontend. """
    # Ensure keys exist gracefully
    status = {
        'eve_logged_in': session.get('eve_logged_in', False),
        'eve_character_name': session.get('eve_character_name', None),
        'eve_roles': session.get('eve_roles', []),
        'site_admin_logged_in': session.get('site_admin_logged_in', False),
        'site_admin_username': session.get('site_admin_username', None)
    }
    return jsonify(status)

@bp.route('/api/character/wallet')
def api_character_wallet():
    """ API: Get character wallet balance. """
    if not session.get('eve_logged_in'):
        return jsonify({"error": "EVE user not authenticated"}), 401

    character_id = session['eve_character_id']
    # Use v1 for wallet balance
    wallet_data = esi_request(f"/characters/{character_id}/wallet/", character_id=character_id, version='v1')

    # Check if esi_request returned an error structure
    if isinstance(wallet_data, dict) and "error" in wallet_data:
         status_code = wallet_data.get("status_code", 502) # Default to 502 Bad Gateway
         return jsonify(wallet_data), status_code

    # ESI returns the balance directly as a float/number
    if isinstance(wallet_data, (int, float)):
        return jsonify({"balance": wallet_data})
    else:
        current_app.logger.error(f"Unexpected wallet data format for {character_id}: {wallet_data}")
        return jsonify({"error": "Unexpected data format from ESI wallet endpoint"}), 500


# --- Skills API Endpoints ---

@bp.route('/api/character/skills')
def api_character_skills():
    """ API: Get character's trained skills list with names. """
    if not session.get('eve_logged_in'):
        return jsonify({"error": "EVE user not authenticated"}), 401

    character_id = session['eve_character_id']
    # Requires esi-skills.read_skills.v1 scope
    # Use v4 for skills endpoint
    skills_data = esi_request(f"/characters/{character_id}/skills/", character_id=character_id, version='v4')

    # Check for errors from esi_request
    if isinstance(skills_data, dict) and "error" in skills_data:
         status_code = skills_data.get("status_code", 502)
         if status_code == 403:
              return jsonify({"error": "Missing required ESI scope (esi-skills.read_skills.v1)"}), 403
         return jsonify(skills_data), status_code

    # Check if the response structure is as expected
    if isinstance(skills_data, dict) and 'skills' in skills_data and 'total_sp' in skills_data:
        # --- Resolve Skill IDs ---
        skill_ids_to_resolve = [s['skill_id'] for s in skills_data.get('skills', []) if 'skill_id' in s]
        resolved_names_map = {}
        if skill_ids_to_resolve:
            resolved_names_map = resolve_ids_to_names(skill_ids_to_resolve) # Use helper

        # Add names to the skill list
        for skill_entry in skills_data.get('skills', []):
            skill_id = skill_entry.get('skill_id')
            if skill_id in resolved_names_map:
                # Use the resolved name, default to ID if resolution failed
                skill_entry['skill_name'] = resolved_names_map[skill_id].get('name', f"ID: {skill_id}")
            else:
                skill_entry['skill_name'] = f"ID: {skill_id}" # Fallback if ID wasn't in response
        # --- End Resolve Skill IDs ---
        return jsonify(skills_data)
    else:
        current_app.logger.error(f"Unexpected skills data format for {character_id}: {skills_data}")
        return jsonify({"error": "Unexpected data format from ESI skills endpoint"}), 500

@bp.route('/api/character/skillqueue')
def api_character_skillqueue():
    """ API: Get character's active skill queue with names. """
    if not session.get('eve_logged_in'):
        return jsonify({"error": "EVE user not authenticated"}), 401

    character_id = session['eve_character_id']
    # Requires esi-skills.read_skillqueue.v1 scope
    # Use v2 for skillqueue endpoint
    queue_data = esi_request(f"/characters/{character_id}/skillqueue/", character_id=character_id, version='v2')

    # Check for errors from esi_request
    if isinstance(queue_data, dict) and "error" in queue_data:
         status_code = queue_data.get("status_code", 502)
         if status_code == 403:
              return jsonify({"error": "Missing required ESI scope (esi-skills.read_skillqueue.v1)"}), 403
         return jsonify(queue_data), status_code

    # ESI returns a list for the skill queue
    if isinstance(queue_data, list):
         # --- Resolve Skill IDs ---
         skill_ids_to_resolve = [s['skill_id'] for s in queue_data if 'skill_id' in s]
         resolved_names_map = {}
         if skill_ids_to_resolve:
              resolved_names_map = resolve_ids_to_names(skill_ids_to_resolve) # Use helper

         # Add names to the queue list
         for queue_entry in queue_data:
              skill_id = queue_entry.get('skill_id')
              if skill_id in resolved_names_map:
                   # Use the resolved name, default to ID if resolution failed
                   queue_entry['skill_name'] = resolved_names_map[skill_id].get('name', f"ID: {skill_id}")
              else:
                   queue_entry['skill_name'] = f"ID: {skill_id}" # Fallback
         # --- End Resolve Skill IDs ---
         return jsonify(queue_data)
    else:
        current_app.logger.error(f"Unexpected skillqueue data format for {character_id}: {queue_data}")
        return jsonify({"error": "Unexpected data format from ESI skillqueue endpoint"}), 500

# --- END Skills API Endpoints ---

# --- Assets API Endpoint ---
@bp.route('/api/character/assets')
def api_character_assets():
    """ API: Get character's assets list with type and location names. """
    if not session.get('eve_logged_in'):
        return jsonify({"error": "EVE user not authenticated"}), 401

    character_id = session['eve_character_id']
    # Requires esi-assets.read_assets.v1 scope
    # Use v5 for assets endpoint
    # TODO: Implement pagination handling for assets (can be very large lists)
    # For now, fetch only the first page. A real implementation needs a loop or async fetching.
    asset_data = esi_request(f"/characters/{character_id}/assets/", character_id=character_id, version='v5', params={'page': 1})

    # Check for errors
    if isinstance(asset_data, dict) and "error" in asset_data:
         status_code = asset_data.get("status_code", 502)
         if status_code == 403:
              return jsonify({"error": "Missing required ESI scope (esi-assets.read_assets.v1)"}), 403
         return jsonify(asset_data), status_code

    # Check response format
    if not isinstance(asset_data, list):
        current_app.logger.error(f"Unexpected assets data format for {character_id}: {asset_data}")
        return jsonify({"error": "Unexpected data format from ESI assets endpoint"}), 500

    # --- Resolve Type IDs and Location IDs ---
    ids_to_resolve = set()
    for item in asset_data:
        if 'type_id' in item:
            ids_to_resolve.add(item['type_id'])
        # Location ID can be a station, structure, solar system, or item ID (for containers)
        if 'location_id' in item:
            ids_to_resolve.add(item['location_id'])

    resolved_names_map = {}
    if ids_to_resolve:
        resolved_names_map = resolve_ids_to_names(list(ids_to_resolve))

    # Add names to the asset list
    for item in asset_data:
        type_id = item.get('type_id')
        location_id = item.get('location_id')

        if type_id in resolved_names_map:
            item['type_name'] = resolved_names_map[type_id].get('name', f"ID: {type_id}")
        else:
            item['type_name'] = f"ID: {type_id}"

        if location_id in resolved_names_map:
            item['location_name'] = resolved_names_map[location_id].get('name', f"ID: {location_id}")
            item['location_category'] = resolved_names_map[location_id].get('category', 'unknown') # Useful for frontend display
        else:
            item['location_name'] = f"ID: {location_id}"
            item['location_category'] = 'unknown'
    # --- End Resolve IDs ---

    # TODO: Consider fetching asset names via POST /characters/{character_id}/assets/names/
    # This might be more efficient for named containers/ships but requires another ESI call.

    return jsonify(asset_data) # Return the enriched list (currently only first page)
# --- END Assets API Endpoint ---

# --- Market Orders API Endpoint ---
@bp.route('/api/character/market_orders')
def api_character_market_orders():
    """ API: Get character's active market orders with type and location names. """
    if not session.get('eve_logged_in'):
        return jsonify({"error": "EVE user not authenticated"}), 401

    character_id = session['eve_character_id']
    # Requires esi-markets.read_character_orders.v1 scope
    # Use v2 for orders endpoint
    orders_data = esi_request(f"/characters/{character_id}/orders/", character_id=character_id, version='v2')

    # Check for errors
    if isinstance(orders_data, dict) and "error" in orders_data:
         status_code = orders_data.get("status_code", 502)
         if status_code == 403:
              return jsonify({"error": "Missing required ESI scope (esi-markets.read_character_orders.v1)"}), 403
         return jsonify(orders_data), status_code

    # Check response format
    if not isinstance(orders_data, list):
        current_app.logger.error(f"Unexpected market orders data format for {character_id}: {orders_data}")
        return jsonify({"error": "Unexpected data format from ESI market orders endpoint"}), 500

    # --- Resolve Type IDs and Location IDs ---
    ids_to_resolve = set()
    for order in orders_data:
        if 'type_id' in order:
            ids_to_resolve.add(order['type_id'])
        if 'location_id' in order: # Station/Structure ID
            ids_to_resolve.add(order['location_id'])
        # region_id is usually less important for display here, but could be added

    resolved_names_map = {}
    if ids_to_resolve:
        resolved_names_map = resolve_ids_to_names(list(ids_to_resolve))

    # Add names to the order list
    for order in orders_data:
        type_id = order.get('type_id')
        location_id = order.get('location_id')

        if type_id in resolved_names_map:
            order['type_name'] = resolved_names_map[type_id].get('name', f"ID: {type_id}")
        else:
            order['type_name'] = f"ID: {type_id}"

        if location_id in resolved_names_map:
            order['location_name'] = resolved_names_map[location_id].get('name', f"ID: {location_id}")
        else:
            order['location_name'] = f"ID: {location_id}"
    # --- End Resolve IDs ---

    return jsonify(orders_data) # Return the enriched list
# --- END Market Orders API Endpoint ---


# --- Contracts API Endpoint ---
@bp.route('/api/character/contracts')
def api_character_contracts():
    """ API: Get character's contracts with relevant names resolved. """
    if not session.get('eve_logged_in'):
        return jsonify({"error": "EVE user not authenticated"}), 401

    character_id = session['eve_character_id']
    # Requires esi-contracts.read_character_contracts.v1 scope
    # Use v1 for contracts endpoint
    # TODO: Implement pagination handling for contracts
    contracts_data = esi_request(f"/characters/{character_id}/contracts/", character_id=character_id, version='v1', params={'page': 1}) # Fetch first page only

    # Check for errors
    if isinstance(contracts_data, dict) and "error" in contracts_data:
         status_code = contracts_data.get("status_code", 502)
         if status_code == 403:
              return jsonify({"error": "Missing required ESI scope (esi-contracts.read_character_contracts.v1)"}), 403
         return jsonify(contracts_data), status_code

    # Check response format
    if not isinstance(contracts_data, list):
        current_app.logger.error(f"Unexpected contracts data format for {character_id}: {contracts_data}")
        return jsonify({"error": "Unexpected data format from ESI contracts endpoint"}), 500

    # --- Resolve IDs ---
    ids_to_resolve = set()
    for contract in contracts_data:
        # Characters, Corporations, Alliances
        if contract.get('issuer_id'): ids_to_resolve.add(contract['issuer_id'])
        if contract.get('issuer_corporation_id'): ids_to_resolve.add(contract['issuer_corporation_id'])
        if contract.get('assignee_id'): ids_to_resolve.add(contract['assignee_id'])
        # Locations (Stations, Structures, Solar Systems)
        if contract.get('start_location_id'): ids_to_resolve.add(contract['start_location_id'])
        if contract.get('end_location_id'): ids_to_resolve.add(contract['end_location_id'])
        # Note: We are NOT resolving item type_ids within contracts here, as that requires
        # a separate call to /characters/{char_id}/contracts/{contract_id}/items/ for each contract.
        # This should be handled by a more detailed contract view if needed.

    resolved_names_map = {}
    if ids_to_resolve:
        resolved_names_map = resolve_ids_to_names(list(ids_to_resolve))

    # Add names to the contract list
    for contract in contracts_data:
        issuer_id = contract.get('issuer_id')
        issuer_corp_id = contract.get('issuer_corporation_id')
        assignee_id = contract.get('assignee_id')
        start_loc_id = contract.get('start_location_id')
        end_loc_id = contract.get('end_location_id')

        contract['issuer_name'] = resolved_names_map.get(issuer_id, {}).get('name', f"ID: {issuer_id}") if issuer_id else "N/A"
        contract['issuer_corporation_name'] = resolved_names_map.get(issuer_corp_id, {}).get('name', f"ID: {issuer_corp_id}") if issuer_corp_id else "N/A"
        contract['assignee_name'] = resolved_names_map.get(assignee_id, {}).get('name', f"ID: {assignee_id}") if assignee_id else "N/A"
        contract['start_location_name'] = resolved_names_map.get(start_loc_id, {}).get('name', f"ID: {start_loc_id}") if start_loc_id else "N/A"
        contract['end_location_name'] = resolved_names_map.get(end_loc_id, {}).get('name', f"ID: {end_loc_id}") if end_loc_id else "N/A"
    # --- End Resolve IDs ---

    return jsonify(contracts_data) # Return the enriched list (currently only first page)
# --- END Contracts API Endpoint ---


@bp.route('/api/audit/<string:character_name>')
def api_audit_character(character_name):
    """ API: Get aggregated data for member audit. """
    # Permission Check: Requires EVE Recruiter/Admin OR Site Admin
    is_eve_recruiter = 'recruiter' in session.get('eve_roles', [])
    is_eve_admin = 'admin' in session.get('eve_roles', [])
    is_site_admin = session.get('site_admin_logged_in', False)

    if not (is_eve_recruiter or is_eve_admin or is_site_admin):
       return jsonify({"error": "Permission denied"}), 403

    # --- Get Character ID ---
    # Use v2 for universe/ids
    id_data = esi_request("/universe/ids/", method='POST', data=[character_name], add_auth_header=False, version='v2')

    if isinstance(id_data, dict) and "error" in id_data:
         status_code = id_data.get("status_code", 502)
         return jsonify({"error": f"Failed to resolve character name: {id_data['error']}"}), status_code
    if not id_data or 'characters' not in id_data or not id_data['characters']:
        return jsonify({"error": f"Character '{character_name}' not found via ESI"}), 404
    target_char_id = id_data['characters'][0]['id']
    resolved_name = id_data['characters'][0]['name']
    # --- End Get Character ID ---


    # --- Make ESI calls for public/semi-public data ---
    # Use esi_request helper (no auth needed for these public endpoints)
    # Use specific versions for stability
    char_info = esi_request(f"/characters/{target_char_id}/", add_auth_header=False, version='v5')
    corp_history_raw = esi_request(f"/characters/{target_char_id}/corporationhistory/", add_auth_header=False, version='v2')

    # --- Aggregate Data ---
    audit_data = {"name": resolved_name, "id": target_char_id}
    ids_to_resolve = set() # Collect IDs that need name resolution

    if isinstance(char_info, dict) and "error" not in char_info:
        audit_data["birthdate"] = char_info.get("birthday")
        audit_data["security_status"] = char_info.get("security_status")
        audit_data["current_corp_id"] = char_info.get("corporation_id")
        audit_data["current_alliance_id"] = char_info.get("alliance_id")
        if audit_data["current_corp_id"]:
             ids_to_resolve.add(audit_data["current_corp_id"])
        if audit_data["current_alliance_id"]:
             ids_to_resolve.add(audit_data["current_alliance_id"])
    else:
        current_app.logger.warning(f"Could not fetch basic char info for audit of {target_char_id}")

    processed_corp_history = []
    if isinstance(corp_history_raw, list):
        for entry in corp_history_raw:
             corp_id = entry.get("corporation_id")
             if corp_id:
                 ids_to_resolve.add(corp_id)
             processed_corp_history.append({
                 "corporation_id": corp_id,
                 "record_id": entry.get("record_id"),
                 "start_date": entry.get("start_date"),
                 #"corporation_name": f"CorpID: {corp_id}" # Name added after resolution
             })
        audit_data["corp_history"] = processed_corp_history # Store processed list
    else:
         current_app.logger.warning(f"Could not fetch corp history for audit of {target_char_id}")
         audit_data["corp_history"] = [{"error": "Failed to fetch history"}]

    # --- Resolve IDs to Names ---
    resolved_names_map = {}
    if ids_to_resolve:
        resolved_names_map = resolve_ids_to_names(list(ids_to_resolve)) # Use helper

    # Update names in audit_data using the map
    corp_id = audit_data.get("current_corp_id")
    audit_data["current_corp_name"] = resolved_names_map.get(corp_id, {}).get('name', f"ID: {corp_id}") if corp_id else "None"

    alliance_id = audit_data.get("current_alliance_id")
    audit_data["current_alliance_name"] = resolved_names_map.get(alliance_id, {}).get('name', f"ID: {alliance_id}") if alliance_id else "None"

    # Update names in the history list
    for entry in audit_data.get("corp_history", []):
        corp_id = entry.get("corporation_id")
        entry["corporation_name"] = resolved_names_map.get(corp_id, {}).get('name', f"ID: {corp_id}") if corp_id else "Unknown"
    # --- End Resolve IDs ---


    # Add placeholders for data requiring target character auth or specific scopes
    audit_data["total_sp"] = "Requires Target Character Auth / Stats Scope"
    audit_data["wallet_balance"] = "Requires Target Character Auth"
    audit_data["skill_queue"] = "Requires Target Character Auth"
    audit_data["asset_locations"] = "Requires Target Character Auth"
    audit_data["mail_count"] = "Requires Target Character Auth"
    # --- End Aggregate Data ---

    return jsonify(audit_data)


# --- Error Handlers ---
@bp.errorhandler(404)
def page_not_found(e):
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({"error": "Not Found", "message": str(e)}), 404
    return "<h1>404 Not Found</h1>", 404

@bp.errorhandler(500)
def internal_server_error(e):
    # Log the actual exception
    current_app.logger.error(f"Server Error: {e}", exc_info=True)
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
      # Avoid sending detailed internal errors to the client in production
      message = "An unexpected internal error occurred." if not current_app.debug else str(e)
      return jsonify({"error": "Internal Server Error", "message": message}), 500
    # Consider a user-friendly HTML error page
    return "<h1>500 Internal Server Error</h1>", 500

@bp.errorhandler(401) # Unauthorized
def unauthorized_error(e):
     if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({"error": "Unauthorized", "message": str(e)}), 401
     flash("You are not authorized to access this page. Please log in.", "danger")
     return redirect(url_for('main.index')) # Or login page

@bp.errorhandler(403) # Forbidden
def forbidden_error(e):
     if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({"error": "Forbidden", "message": str(e)}), 403
     flash("You do not have permission to perform this action.", "danger")
     return redirect(url_for('main.index'))

