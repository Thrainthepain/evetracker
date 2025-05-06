    # app/utils.py
    # Helper functions for ESI interactions, token handling, etc.

    import base64
    import datetime
    import time
    import requests
    import jwt # PyJWT library
    from cryptography.fernet import Fernet, InvalidToken
    from flask import current_app, session, flash
    from urllib.parse import urljoin, urlencode
    import os # Added for state generation
    from email.utils import parsedate_to_datetime # For parsing Expires header
    import threading # For cache lock

    from app import db
    from app.models import EveCharacter

    # --- Token Encryption/Decryption ---

    def get_cipher():
        """Initializes the Fernet cipher with the key from config."""
        key = current_app.config.get('REFRESH_TOKEN_ENCRYPTION_KEY')
        if not key:
            current_app.logger.error("REFRESH_TOKEN_ENCRYPTION_KEY not set in config!")
            return None
        try:
            # Ensure key is bytes
            key_bytes = key.encode() if isinstance(key, str) else key
            # Ensure key is urlsafe base64 encoded
            # Fernet requires a 32-byte url-safe base64-encoded key
            # If the key from config isn't correct, Fernet() will raise an error
            return Fernet(key_bytes)
        except Exception as e:
            current_app.logger.error(f"Failed to initialize cipher, key might be invalid or not set: {e}")
            return None


    def encrypt_token(token):
        """Encrypts a token string."""
        cipher = get_cipher()
        if not cipher or not token:
            return None
        try:
            return cipher.encrypt(token.encode())
        except Exception as e:
             current_app.logger.error(f"Encryption failed: {e}")
             return None

    def decrypt_token(encrypted_token_bytes):
        """Decrypts an encrypted token (bytes)."""
        cipher = get_cipher()
        if not cipher or not encrypted_token_bytes:
            return None
        try:
            return cipher.decrypt(encrypted_token_bytes).decode()
        except InvalidToken:
            current_app.logger.error("Failed to decrypt token: Invalid token (key mismatch or corrupted data?)")
            return None
        except Exception as e:
            current_app.logger.error(f"Failed to decrypt token: {e}")
            return None

    # --- ESI Request Helper ---

    _esi_error_limit_remaining = 100
    _esi_error_limit_reset = 0

    # --- Basic In-Memory ESI Cache ---
    # Structure: { cache_key: {'etag': '...', 'expires': timestamp, 'data': ...} }
    # NOTE: This cache is per-process and lost on restart. Use Redis/Memcached for production.
    _esi_response_cache = {}
    _ESI_CACHE_LOCK = threading.Lock() # Basic lock for thread safety on cache dict

    # --- ESI Request Helper ---

    def esi_request(endpoint, character_id=None, params=None, method='GET', data=None, add_auth_header=True, version='latest'):
        """
        Makes a request to the EVE ESI API.
        Handles authentication, basic error handling, User-Agent, and basic ETag/Expires caching.
        """
        global _esi_error_limit_remaining, _esi_error_limit_reset, _esi_response_cache

        # --- Create Cache Key ---
        # Needs to uniquely identify the request based on relevant factors
        # Sorting params ensures consistent key regardless of query param order
        sorted_params = urlencode(sorted(params.items())) if params else ''
        # Include method in key for safety, although most GETs are cached
        cache_key = f"{method}:{endpoint}:{version}:{character_id or 'None'}:{sorted_params}"
        # Note: 'data' for POST/PUT is not included in this simple key, caching might be less effective/correct for those.

        now_dt = datetime.datetime.now(datetime.timezone.utc) # Use timezone-aware datetime
        now_ts = now_dt.timestamp()
        cached_response = None
        cached_etag = None

        # --- Check Cache ---
        if method == 'GET': # Only cache GET requests for simplicity
            with _ESI_CACHE_LOCK:
                if cache_key in _esi_response_cache:
                    cached_entry = _esi_response_cache[cache_key]
                    # Check if cache entry has expired
                    if cached_entry['expires'] > now_ts:
                        current_app.logger.debug(f"ESI Cache HIT (Fresh): {cache_key}")
                        return cached_entry['data'] # Return fresh data
                    else:
                        # Cache entry expired, but we might have an ETag
                        current_app.logger.debug(f"ESI Cache HIT (Expired): {cache_key}")
                        cached_response = cached_entry['data'] # Keep data in case of 304
                        cached_etag = cached_entry.get('etag') # Get ETag if it exists
        # --- End Check Cache ---


        # Check error limit before making request
        if _esi_error_limit_remaining < 5: # Leave a small buffer
            if now_ts < _esi_error_limit_reset:
                wait_time = _esi_error_limit_reset - now_ts
                current_app.logger.warning(f"ESI error limit approaching. Waiting for {wait_time:.1f}s.")
                time.sleep(wait_time + 1) # Wait until reset plus a buffer

        access_token = None
        if character_id and add_auth_header:
            access_token = get_esi_access_token(character_id)
            if not access_token:
                current_app.logger.error(f"Cannot perform ESI request for char {character_id}: No valid access token.")
                return {"error": "Invalid or expired ESI token", "status_code": 401}

        # Construct URL using base and version
        # Ensure base URL doesn't have /latest if version is provided
        base_url_root = current_app.config['ESI_BASE_URL'].replace('/latest', '')
        base_url = f"{base_url_root}/{version}"
        url = urljoin(base_url.strip('/') + '/', endpoint.lstrip('/')) # Ensure correct joining

        headers = {
            'Accept': 'application/json',
            'User-Agent': f"{current_app.config['APP_NAME']}/{current_app.config['APP_VERSION']} ({current_app.config['APP_CONTACT_EMAIL']})",
            # 'Cache-Control': 'no-cache' # Remove this when using ETag/Expires
        }
        if access_token:
            headers['Authorization'] = f'Bearer {access_token}'
        # --- Add ETag header if we have an expired cache entry ---
        if cached_etag and method == 'GET': # Only send ETag for GET
            headers['If-None-Match'] = cached_etag
            current_app.logger.debug(f"Sending If-None-Match header: {cached_etag}")
        # --- End Add ETag ---

        response = None
        try:
            current_app.logger.debug(f"ESI Request: {method} {url} Params: {params} Auth: {bool(access_token)} ETag: {cached_etag}")
            response = requests.request(method, url, headers=headers, params=params, json=data, timeout=15) # Added timeout

            # Update error limit tracking from headers
            if 'X-Esi-Error-Limit-Remain' in response.headers:
                _esi_error_limit_remaining = int(response.headers['X-Esi-Error-Limit-Remain'])
            if 'X-Esi-Error-Limit-Reset' in response.headers:
                _esi_error_limit_reset = time.time() + int(response.headers['X-Esi-Error-Limit-Reset'])
            current_app.logger.debug(f"ESI Error Limit: {_esi_error_limit_remaining} / {_esi_error_limit_reset - time.time():.0f}s")

            # --- Handle 304 Not Modified ---
            if response.status_code == 304 and method == 'GET':
                current_app.logger.debug(f"ESI Response 304 Not Modified for {cache_key}. Using cached data.")
                # Update expiry time in cache based on new Expires header, but keep old data and ETag
                expires_header = response.headers.get('Expires')
                expires_ts = now_ts + 60 # Default short expiry if header missing
                if expires_header:
                    try:
                        expires_dt = parsedate_to_datetime(expires_header)
                        # Ensure it's timezone-aware (ESI *should* send GMT)
                        if expires_dt.tzinfo is None:
                             expires_dt = expires_dt.replace(tzinfo=datetime.timezone.utc)
                        expires_ts = expires_dt.timestamp()
                    except Exception as e:
                        current_app.logger.warning(f"Could not parse Expires header '{expires_header}': {e}")

                with _ESI_CACHE_LOCK:
                    if cache_key in _esi_response_cache: # Check if still exists
                         _esi_response_cache[cache_key]['expires'] = expires_ts # Update expiry
                return cached_response # Return the previously cached data
            # --- End Handle 304 ---

            if response.status_code == 420:
                 current_app.logger.warning("ESI Error Limit Reached (420). Waiting...")
                 wait_time = int(response.headers.get('X-Esi-Error-Limit-Reset', 60))
                 time.sleep(wait_time + 1)
                 return {"error": "ESI error limit reached", "status_code": 420}

            response.raise_for_status() # Raise HTTPError for other bad responses (4xx or 5xx)

            # --- Process Successful Response (2xx) ---
            response_data = None
            if response.status_code == 204: # No Content
                response_data = None
            else:
                # Check content type before assuming JSON
                content_type = response.headers.get('content-type', '')
                if 'application/json' in content_type:
                    try:
                        response_data = response.json()
                    except requests.exceptions.JSONDecodeError as json_err:
                         current_app.logger.error(f"Failed to decode JSON response for {url}: {json_err}. Response text: {response.text[:200]}")
                         return {"error": "Invalid JSON received from ESI", "status_code": 502}
                else:
                    # Handle non-JSON responses if necessary, or log warning
                    current_app.logger.warning(f"Received non-JSON response for {url}. Content-Type: {content_type}")
                    response_data = response.text # Return raw text? Or error?

            # --- Update Cache (Only for GET requests) ---
            if method == 'GET':
                etag = response.headers.get('ETag')
                expires_header = response.headers.get('Expires')
                expires_ts = now_ts + 60 # Default short expiry if header missing/unparsable

                if expires_header:
                    try:
                        expires_dt = parsedate_to_datetime(expires_header)
                        if expires_dt.tzinfo is None:
                            expires_dt = expires_dt.replace(tzinfo=datetime.timezone.utc)
                        expires_ts = expires_dt.timestamp()
                    except Exception as e:
                        current_app.logger.warning(f"Could not parse Expires header '{expires_header}': {e}")

                # Only cache if we have an expiry time in the future
                if expires_ts > now_ts:
                    cache_entry = {'expires': expires_ts, 'data': response_data}
                    if etag:
                        # ETag includes quotes, store them as ESI expects them back
                        cache_entry['etag'] = etag
                    else:
                        # If no ETag, remove old one from cache entry if it exists
                         cache_entry.pop('etag', None)

                    with _ESI_CACHE_LOCK:
                        _esi_response_cache[cache_key] = cache_entry
                    current_app.logger.debug(f"Cached ESI response for {cache_key}. Expires: {datetime.datetime.fromtimestamp(expires_ts, tz=datetime.timezone.utc)}")
                else:
                     current_app.logger.debug(f"Not caching ESI response for {cache_key} due to past/invalid expiry.")
                     # If expiry is invalid/past, remove any old cache entry
                     with _ESI_CACHE_LOCK:
                         _esi_response_cache.pop(cache_key, None)
            # --- End Update Cache ---

            return response_data
            # --- End Process Successful Response ---

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response is not None else 500
            error_message = f"ESI HTTP Error {status_code}"
            try:
                # Try to get ESI's specific error message
                esi_error = e.response.json().get('error', 'Unknown ESI Error') if e.response is not None else 'No Response'
                error_message += f": {esi_error}"
            except (ValueError, AttributeError, requests.exceptions.JSONDecodeError): # If response is not JSON or no response
                error_text = e.response.text[:100] if e.response is not None else "N/A"
                error_message += f": {error_text}" # Include start of text
            current_app.logger.error(f"{error_message} accessing {url}")
            # Remove potentially invalid cache entry on error
            if method == 'GET':
                with _ESI_CACHE_LOCK:
                    _esi_response_cache.pop(cache_key, None)
            return {"error": error_message, "status_code": status_code}
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"ESI Request Exception for {url}: {e}")
            return {"error": f"ESI request failed: {e}", "status_code": 503} # Service Unavailable maybe?
        except Exception as e:
            current_app.logger.error(f"Unexpected error during ESI request for {url}: {e}", exc_info=True)
            return {"error": f"An unexpected error occurred: {e}", "status_code": 500}


    # --- ESI Token Refresh and Verification ---

    # Cache for JWKS keys to avoid fetching them repeatedly
    _jwks_cache = None
    _jwks_cache_time = 0

    def get_jwks():
        """Fetches and caches ESI's JWKS keys."""
        global _jwks_cache, _jwks_cache_time
        cache_duration = 3600 # Cache keys for 1 hour
        now = time.time()

        if _jwks_cache and (now - _jwks_cache_time < cache_duration):
            return _jwks_cache

        try:
            jwks_url = current_app.config['EVE_OAUTH_JWKS_URL']
            response = requests.get(jwks_url, timeout=10)
            response.raise_for_status()
            _jwks_cache = response.json()
            _jwks_cache_time = now
            current_app.logger.info("Fetched and cached new ESI JWKS keys.")
            return _jwks_cache
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Failed to fetch ESI JWKS keys: {e}")
            return _jwks_cache # Return stale cache if fetch fails? Or None?
        except Exception as e:
            current_app.logger.error(f"Error processing JWKS keys: {e}", exc_info=True)
            return None

    def verify_esi_jwt(access_token):
        """Verifies the ESI Access Token (JWT) and returns its claims."""
        jwks = get_jwks()
        if not jwks:
            raise Exception("Could not retrieve JWKS keys for token verification.")

        try:
            # Get the kid from the token header
            header = jwt.get_unverified_header(access_token)
            kid = header.get('kid')
            if not kid:
                 raise jwt.exceptions.DecodeError("Token header missing 'kid'.")

            # Find the key in the JWKS set
            public_key = None
            for key in jwks['keys']:
                if key['kid'] == kid:
                    # Construct the public key using jwt library's helper
                    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
                    break

            if not public_key:
                raise jwt.exceptions.DecodeError(f"Public key with kid '{kid}' not found in JWKS.")

            # Decode and verify the token
            payload = jwt.decode(
                access_token,
                public_key,
                algorithms=["RS256"],
                audience="EVE Online", # Verify audience claim
                # Issuer changed for v2 endpoint
                issuer=["login.eveonline.com", "https://login.eveonline.com"], # Accept either format
                # options={"verify_iss": True} # Ensure issuer verification is active
            )
            # Additional checks (optional but recommended)
            if not payload.get('sub') or not payload['sub'].startswith('CHARACTER:EVE:'):
                 raise jwt.exceptions.InvalidTokenError("Invalid 'sub' claim in token.")

            return payload

        except jwt.ExpiredSignatureError:
            current_app.logger.warning("ESI JWT verification failed: Token has expired.")
            raise # Re-raise specific exception
        except jwt.InvalidTokenError as e:
            current_app.logger.error(f"ESI JWT verification failed: {e}")
            raise # Re-raise specific exception
        except Exception as e:
            current_app.logger.error(f"Unexpected error during JWT verification: {e}", exc_info=True)
            raise Exception(f"Token verification failed unexpectedly: {e}")


    def refresh_esi_token(character_id, decrypted_refresh_token):
        """Uses a refresh token to get a new access token from EVE SSO."""
        token_url = current_app.config['EVE_OAUTH_TOKEN_URL']
        client_id = current_app.config['ESI_CLIENT_ID']
        client_secret = current_app.config['ESI_SECRET_KEY']

        if not client_id or not client_secret:
            current_app.logger.error("ESI_CLIENT_ID or ESI_SECRET_KEY not configured.")
            return None, None, None # Indicate failure

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
            'grant_type': 'refresh_token',
            'refresh_token': decrypted_refresh_token
        }

        try:
            current_app.logger.info(f"Attempting ESI token refresh for character {character_id}")
            response = requests.post(token_url, headers=headers, data=data, timeout=15)
            response.raise_for_status() # Raise HTTPError for bad status codes (e.g., 400 invalid_grant)

            token_data = response.json()
            new_access_token = token_data['access_token']
            new_refresh_token = token_data.get('refresh_token') # EVE might issue a new refresh token
            expires_in = token_data['expires_in']

            current_app.logger.info(f"ESI token refresh successful for character {character_id}")
            return new_access_token, new_refresh_token, expires_in

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            error_details = e.response.text[:200] # Log start of response text
            current_app.logger.error(f"ESI token refresh failed for char {character_id}. Status: {status_code}. Error: {error_details}. Exception: {e}")
            # If refresh token is invalid (e.g., 400 invalid_grant), we need to mark it as such
            if status_code == 400:
                 try:
                     err_json = e.response.json()
                     if err_json.get("error") == "invalid_grant":
                         # Mark token as invalid in DB?
                         character = EveCharacter.query.get(character_id)
                         if character:
                             current_app.logger.warning(f"Marking refresh token as invalid for char {character_id} due to invalid_grant.")
                             character.encrypted_refresh_token = None # Or a specific marker?
                             character.token_last_validated = datetime.datetime.utcnow() # Mark validation time
                             try:
                                 db.session.commit()
                             except Exception as db_err:
                                 db.session.rollback()
                                 current_app.logger.error(f"DB Error marking token invalid for {character_id}: {db_err}")
                 except (ValueError, requests.exceptions.JSONDecodeError):
                     pass # Response wasn't json
            return None, None, None # Indicate failure
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Network error during ESI token refresh for char {character_id}: {e}")
            return None, None, None
        except Exception as e:
             current_app.logger.error(f"Unexpected error during token refresh for char {character_id}: {e}", exc_info=True)
             return None, None, None


    # --- Access Token Management ---

    # Simple in-memory cache for access tokens (replace with Redis/Memcached for multi-process)
    _access_token_cache = {} # {character_id: {'token': '...', 'expires_at': timestamp}}
    _ACCESS_TOKEN_CACHE_LOCK = threading.Lock() # Lock for access token cache

    def get_esi_access_token(character_id):
        """
        Gets a valid access token for the character, refreshing if necessary.
        Uses a simple in-memory cache.
        """
        now = time.time()

        # Check cache first
        with _ACCESS_TOKEN_CACHE_LOCK:
            if character_id in _access_token_cache:
                cached = _access_token_cache[character_id]
                # Check expiry (with a 60-second buffer)
                if cached['expires_at'] > now + 60:
                    current_app.logger.debug(f"Using cached access token for char {character_id}")
                    return cached['token']
                else:
                    current_app.logger.debug(f"Cached access token expired for char {character_id}")
                    # Don't delete immediately, let refresh logic handle it
                    # del _access_token_cache[character_id] # Remove expired entry

        # If not in cache or expired, fetch from DB and potentially refresh
        character = EveCharacter.query.get(character_id)
        if not character or not character.encrypted_refresh_token:
            current_app.logger.warning(f"No character or refresh token found for ID {character_id}")
            # Clear cache entry if character/token missing in DB
            with _ACCESS_TOKEN_CACHE_LOCK:
                _access_token_cache.pop(character_id, None)
            return None

        decrypted_refresh_token = decrypt_token(character.encrypted_refresh_token)
        if not decrypted_refresh_token:
            current_app.logger.error(f"Failed to decrypt refresh token for char {character_id}")
            # Mark token as invalid? Clear cache?
            with _ACCESS_TOKEN_CACHE_LOCK:
                _access_token_cache.pop(character_id, None)
            return None

        # Attempt refresh
        new_access_token, new_refresh_token_optional, expires_in = refresh_esi_token(character_id, decrypted_refresh_token)

        if not new_access_token:
            current_app.logger.error(f"Failed to refresh token for char {character_id}")
            # Mark token as invalid? Could trigger re-auth requirement.
            # Clear cache entry on refresh failure
            with _ACCESS_TOKEN_CACHE_LOCK:
                 _access_token_cache.pop(character_id, None)
            return None

        # Update database if a new refresh token was issued
        token_updated_in_db = False
        if new_refresh_token_optional:
            current_app.logger.info(f"Updating refresh token for char {character_id}")
            new_encrypted_refresh = encrypt_token(new_refresh_token_optional)
            if new_encrypted_refresh:
                character.encrypted_refresh_token = new_encrypted_refresh
                token_updated_in_db = True
            else:
                 current_app.logger.error(f"Failed to encrypt NEW refresh token for char {character_id}")
                 # Continue with the old one for now? Or fail?

        # Update token validation time (or maybe a separate 'last_refresh_success' time?)
        character.token_last_validated = datetime.datetime.utcnow() # Or maybe just update on successful ESI call?
        token_updated_in_db = True # Mark DB needs update even if only timestamp changed

        if token_updated_in_db:
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"DB Error updating token info for char {character_id}: {e}")
                # Proceed with the new access token anyway, but log the DB error

        # Store the new access token in the cache
        if expires_in is None:
            expires_in = 3600 # Default expiry if not provided? Should not happen.
        expires_at = now + expires_in
        with _ACCESS_TOKEN_CACHE_LOCK:
            _access_token_cache[character_id] = {'token': new_access_token, 'expires_at': expires_at}
        current_app.logger.debug(f"Cached new access token for char {character_id}, expires in {expires_in}s")

        return new_access_token

    # --- ID to Name Resolution ---
    _name_cache = {} # Simple in-memory cache: {id: {'name': '...', 'category': '...', 'expires': timestamp}}
    _NAME_CACHE_DURATION = 24 * 3600 # Cache names for 24 hours
    _NAME_CACHE_LOCK = threading.Lock() # Lock for name cache

    def resolve_ids_to_names(id_list):
        """
        Resolves a list of EVE IDs (character, corporation, alliance, item type, etc.) to names.
        Uses the /universe/names/ ESI endpoint and includes basic caching.
        Returns a dictionary mapping ID to {'name': '...', 'category': '...'}.
        """
        if not id_list:
            return {}

        # Ensure all IDs are integers and filter out None/invalid values
        try:
            input_ids = list(set(int(i) for i in id_list if i is not None)) # Use set for uniqueness, then list
        except (ValueError, TypeError) as e:
            current_app.logger.error(f"Invalid ID list provided to resolve_ids_to_names: {id_list} - Error: {e}")
            return {}
        if not input_ids: # Handle empty list after filtering
            return {}


        resolved_names = {}
        ids_to_fetch = []
        now = time.time()

        # Check cache first
        with _NAME_CACHE_LOCK:
            for item_id in input_ids:
                if item_id in _name_cache:
                    cached = _name_cache[item_id]
                    if cached['expires'] > now:
                        resolved_names[item_id] = {'name': cached['name'], 'category': cached['category']}
                    else:
                        # Expired cache entry
                        del _name_cache[item_id]
                        ids_to_fetch.append(item_id)
                else:
                    ids_to_fetch.append(item_id)

        if not ids_to_fetch:
            return resolved_names # All names were cached

        # ESI /universe/names/ endpoint accepts up to 1000 IDs per request
        chunk_size = 1000
        for i in range(0, len(ids_to_fetch), chunk_size):
            chunk = ids_to_fetch[i:i + chunk_size]
            current_app.logger.info(f"Resolving {len(chunk)} IDs to names via ESI /universe/names/")

            # Make POST request (no auth needed)
            response_data = esi_request(
                endpoint="/universe/names/",
                method='POST',
                data=chunk, # Send list of IDs in request body
                add_auth_header=False,
                version='v3' # Use specific version
            )

            if isinstance(response_data, list):
                # Process successful response
                cache_expiry_time = now + _NAME_CACHE_DURATION
                with _NAME_CACHE_LOCK: # Lock during cache update
                    for item in response_data:
                        item_id = item.get('id')
                        name = item.get('name')
                        category = item.get('category')
                        if item_id and name and category:
                            resolved_names[item_id] = {'name': name, 'category': category}
                            # Add to cache
                            _name_cache[item_id] = {'name': name, 'category': category, 'expires': cache_expiry_time}
            elif isinstance(response_data, dict) and 'error' in response_data:
                # Handle error from esi_request
                current_app.logger.error(f"Failed to resolve names chunk: {response_data['error']}")
                # You might want to return partial results or indicate failure for specific IDs
            else:
                 current_app.logger.error(f"Unexpected response format from /universe/names/: {response_data}")


        # Return all resolved names (from cache and newly fetched)
        return resolved_names
    