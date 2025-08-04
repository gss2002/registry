#!/usr/bin/env python3
"""
MCP Registry Client with PKCE Authentication
Python script that:
1. Gets OIDC bearer token from Dex using PKCE (no client secret needed)
2. Calls existing MCP registry server with JSON payload
3. Publishes server entry to the registry
"""
import argparse
import base64
import hashlib
import json
import os
import secrets
import socket
import sys
import urllib.parse
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import time
import requests


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth callback"""
    
    def do_GET(self):
        # Parse query parameters
        parsed_url = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Store the authorization code and state
        self.server.auth_code = query_params.get('code', [None])[0]
        self.server.auth_state = query_params.get('state', [None])[0]
        self.server.auth_error = query_params.get('error', [None])[0]
        
        # Send response to browser
        if self.server.auth_error:
            self.send_response(400)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f"""
                <html>
                <head><title>Authentication Error</title></head>
                <body>
                    <h1>Authentication Error</h1>
                    <p>Error: {self.server.auth_error}</p>
                    <p>You can close this window.</p>
                </body>
                </html>
            """.encode())
        elif self.server.auth_code:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"""
                <html>
                <head><title>Authentication Successful</title></head>
                <body>
                    <h1>Authentication Successful!</h1>
                    <p>You can now close this window and return to the terminal.</p>
                </body>
                </html>
            """)
        else:
            self.send_response(400)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"""
                <html>
                <head><title>Authentication Failed</title></head>
                <body>
                    <h1>Authentication Failed</h1>
                    <p>No authorization code received.</p>
                    <p>You can close this window.</p>
                </body>
                </html>
            """)
    
    def log_message(self, format, *args):
        # Suppress HTTP server logs
        pass


class MCPRegistryClient:
    def __init__(self, registry_url, issuer_url, client_id, redirect_port=8080, verbose=False):
        self.registry_url = registry_url.rstrip('/')
        self.issuer_url = issuer_url.rstrip('/')
        self.client_id = client_id
        self.redirect_port = redirect_port
        self.redirect_uri = f"http://localhost:{redirect_port}/callback"
        self.verbose = verbose
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None
        
        # Token storage
        home_dir = Path.home()
        self.token_file = home_dir / '.mcp-registry' / 'oidc-pkce-token.json'
        
    def log(self, message):
        if self.verbose:
            print(f"[DEBUG] {message}")
            
    def info(self, message):
        print(f"[INFO] {message}")
    
    def discover_oidc_endpoints(self):
        """Discover OIDC endpoints from well-known configuration"""
        discovery_url = f"{self.issuer_url}/.well-known/openid-configuration"
        self.log(f"Discovering OIDC endpoints at: {discovery_url}")
        
        try:
            response = requests.get(discovery_url, timeout=10)
            response.raise_for_status()
            config = response.json()
            
            self.auth_endpoint = config['authorization_endpoint']
            self.token_endpoint = config['token_endpoint']
            self.device_endpoint = config.get('device_authorization_endpoint')
            
            self.log(f"Authorization endpoint: {self.auth_endpoint}")
            self.log(f"Token endpoint: {self.token_endpoint}")
            if self.device_endpoint:
                self.log(f"Device authorization endpoint: {self.device_endpoint}")
            else:
                self.log("Device authorization endpoint not found in discovery")
            return True
            
        except requests.RequestException as e:
            print(f"❌ Error: Failed to discover OIDC endpoints: {e}")
            return False
        except KeyError as e:
            print(f"❌ Error: Missing required endpoint in discovery document: {e}")
            return False
    
    def find_available_port(self, start_port=8080, max_attempts=10):
        """Find an available port starting from start_port"""
        for port in range(start_port, start_port + max_attempts):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('localhost', port))
                    self.log(f"Found available port: {port}")
                    return port
            except OSError:
                continue
        
        # If no port found in range, let system assign one
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('localhost', 0))
            port = s.getsockname()[1]
            self.log(f"Using system-assigned port: {port}")
            return port
    def generate_pkce_challenge(self):
        """Generate PKCE code verifier and challenge"""
        # Generate code verifier (43-128 characters)
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Generate code challenge (SHA256 hash of verifier, base64url encoded)
        challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')
        
        self.log(f"Generated PKCE verifier: {code_verifier[:20]}...")
        self.log(f"Generated PKCE challenge: {code_challenge[:20]}...")
        
        return code_verifier, code_challenge
    
    def get_access_token_pkce(self, scopes=None, use_device_flow=False, use_client_credentials=False):
        """Get OIDC access token using various flows"""
        if scopes is None:
            scopes = ['openid', 'profile', 'email']
        
        # Try to load existing token first
        if self.load_stored_token():
            if self.is_token_valid():
                self.info("✅ Using cached OIDC token")
                return True
            elif self.refresh_token:
                if self.refresh_access_token():
                    self.info("✅ Refreshed OIDC token")
                    return True
        
        if use_client_credentials:
            return self.get_access_token_client_credentials(scopes)
        elif use_device_flow:
            return self.get_access_token_device_flow(scopes)
        else:
            return self.get_access_token_browser_flow(scopes)
    
    def get_access_token_client_credentials(self, scopes=None):
        """Get OIDC access token using client credentials flow (for service accounts)"""
        if scopes is None:
            scopes = ['openid', 'profile']
        
        # This requires client_secret to be configured
        client_secret = os.getenv('OIDC_CLIENT_SECRET')
        if not client_secret:
            print("❌ Error: Client credentials flow requires OIDC_CLIENT_SECRET environment variable")
            return False
        
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': client_secret,
            'scope': ' '.join(scopes)
        }
        
        self.log(f"Requesting client credentials token from: {self.token_endpoint}")
        
        try:
            response = requests.post(
                self.token_endpoint,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=10
            )
            
            if response.status_code != 200:
                print(f"❌ Error: Token request failed with status {response.status_code}")
                print(f"Response: {response.text}")
                return False
            
            token_data = response.json()
            self.access_token = token_data.get('access_token')
            
            if not self.access_token:
                print(f"❌ Error: No access_token in response")
                return False
            
            expires_in = token_data.get('expires_in', 3600)
            self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)
            
            # Store token (no refresh token in client credentials)
            self.store_token()
            
            self.info(f"✅ Client credentials token obtained successfully")
            self.log(f"Token expires at: {self.token_expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
            return True
            
        except requests.RequestException as e:
            print(f"❌ Error: Failed to request token: {e}")
            return False
    def get_access_token_device_flow(self, scopes):
        """Get OIDC access token using device authorization flow"""
        # Check if device authorization endpoint is available
        if not hasattr(self, 'device_endpoint') or not self.device_endpoint:
            # Try common device endpoint paths
            possible_endpoints = [
                f"{self.issuer_url}/device/code",
                f"{self.issuer_url}/oauth/device/code", 
                f"{self.issuer_url}/device_authorization",
                f"{self.token_endpoint.replace('/token', '/device/code')}"
            ]
            
            self.log("Device endpoint not in discovery, trying common paths...")
            for endpoint in possible_endpoints:
                self.log(f"Trying device endpoint: {endpoint}")
                if self._test_device_endpoint(endpoint):
                    self.device_endpoint = endpoint
                    break
            
            if not hasattr(self, 'device_endpoint') or not self.device_endpoint:
                self.info("❌ Device authorization not supported by this OIDC provider")
                return False
        
        self.info("🔧 Starting device authorization flow...")
        self.log(f"Using device endpoint: {self.device_endpoint}")
        
        # Step 1: Request device and user codes
        device_data = {
            'client_id': self.client_id,
            'scope': ' '.join(scopes)
        }
        
        try:
            response = requests.post(
                self.device_endpoint,
                data=device_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=10
            )
            
            self.log(f"Device request status: {response.status_code}")
            self.log(f"Device request response: {response.text}")
            
            if response.status_code != 200:
                print(f"❌ Device authorization failed: {response.status_code} - {response.text}")
                return False
            
            device_response = response.json()
            
        except requests.RequestException as e:
            print(f"❌ Device authorization request failed: {e}")
            return False
        
        # Extract device flow parameters
        device_code = device_response.get('device_code')
        user_code = device_response.get('user_code')
        verification_uri = device_response.get('verification_uri')
        verification_uri_complete = device_response.get('verification_uri_complete')
        expires_in = device_response.get('expires_in', 600)
        interval = device_response.get('interval', 5)
        
        if not all([device_code, user_code, verification_uri]):
            print(f"❌ Invalid device flow response: {device_response}")
            return False
        
        # Display instructions to user
        print("\n" + "="*60)
        print("🔐 DEVICE AUTHENTICATION REQUIRED")
        print("="*60)
        print(f"1. Open this URL in a browser (on any device):")
        print(f"   {verification_uri}")
        print(f"")
        print(f"2. Enter this code: {user_code}")
        print(f"")
        if verification_uri_complete:
            print(f"OR use this direct link (includes code):")
            print(f"   {verification_uri_complete}")
            print(f"")
        print(f"⏱️  Code expires in {expires_in//60} minutes")
        print("="*60)
        print("Waiting for you to complete authentication...")
        
        # Step 2: Poll for token
        start_time = time.time()
        while time.time() - start_time < expires_in:
            time.sleep(interval)
            
            token_data = {
                'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                'client_id': self.client_id,
                'device_code': device_code
            }
            
            try:
                response = requests.post(
                    self.token_endpoint,
                    data=token_data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    timeout=10
                )
                
                self.log(f"Token poll status: {response.status_code}")
                self.log(f"Token poll response: {response.text}")
                
                if response.status_code == 200:
                    # Success!
                    token_response = response.json()
                    self.access_token = token_response.get('access_token')
                    self.refresh_token = token_response.get('refresh_token')
                    
                    if not self.access_token:
                        print("❌ Error: No access_token in response")
                        return False
                    
                    expires_in_token = token_response.get('expires_in', 3600)
                    self.token_expires_at = datetime.now() + timedelta(seconds=expires_in_token)
                    
                    # Store tokens
                    self.store_token()
                    
                    print("✅ Device authentication successful!")
                    self.info(f"Token expires at: {self.token_expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
                    return True
                
                elif response.status_code in [400, 401]:  # Handle both 400 and 401 for pending auth
                    try:
                        error_response = response.json()
                        error = error_response.get('error', 'unknown_error')
                    except json.JSONDecodeError:
                        error = 'unknown_error'
                    
                    if error == 'authorization_pending':
                        # Still waiting for user to complete auth
                        print("⏳ Still waiting for authentication...")
                        continue
                    elif error == 'slow_down':
                        # Increase polling interval
                        interval = min(interval * 2, 30)
                        print("⏳ Slowing down polling...")
                        continue
                    elif error == 'expired_token':
                        print("❌ Authentication code expired. Please try again.")
                        return False
                    elif error == 'access_denied':
                        print("❌ Authentication was denied.")
                        return False
                    else:
                        print(f"❌ Authentication error: {error}")
                        return False
                
                else:
                    print(f"❌ Unexpected response: {response.status_code} - {response.text}")
                    return False
                    
            except requests.RequestException as e:
                print(f"❌ Error polling for token: {e}")
                return False
        
        print("❌ Authentication timeout. Please try again.")
        return False
    
    def _test_device_endpoint(self, endpoint):
        """Test if a device endpoint is available"""
        try:
            response = requests.post(
                endpoint,
                data={'client_id': 'test'},
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=5
            )
            # If we get any response (even error), endpoint exists
            return response.status_code in [200, 400, 401]
        except:
            return False
    
    def get_access_token_browser_flow(self, scopes):
        """Get OIDC access token using browser-based PKCE flow"""
        
        # Generate PKCE parameters
        code_verifier, code_challenge = self.generate_pkce_challenge()
        state = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Find an available port
        available_port = self.find_available_port(self.redirect_port)
        if available_port != self.redirect_port:
            self.info(f"📡 Port {self.redirect_port} in use, using port {available_port} instead")
            actual_redirect_uri = f"http://localhost:{available_port}/callback"
        else:
            actual_redirect_uri = self.redirect_uri
        # Build authorization URL
        auth_params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': actual_redirect_uri,
            'scope': ' '.join(scopes),
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        auth_url = f"{self.auth_endpoint}?{urllib.parse.urlencode(auth_params)}"
        
        self.info("🌐 Starting PKCE authentication flow...")
        self.info(f"Opening browser for authentication: {auth_url}")
        
        # Start local callback server
        server = HTTPServer(('localhost', available_port), CallbackHandler)
        server.auth_code = None
        server.auth_state = None
        server.auth_error = None
        
        # Start server in background thread
        server_thread = Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        
        try:
            # Open browser
            if not webbrowser.open(auth_url):
                print(f"❌ Failed to open browser automatically.")
                print(f"Please open this URL manually: {auth_url}")
            
            # Wait for callback (max 5 minutes)
            timeout = time.time() + 300  # 5 minutes
            while server.auth_code is None and server.auth_error is None and time.time() < timeout:
                time.sleep(0.5)
            
            # Stop server
            server.shutdown()
            
            if server.auth_error:
                print(f"❌ Authentication error: {server.auth_error}")
                return False
            
            if not server.auth_code:
                print(f"❌ Authentication timeout or no authorization code received")
                return False
            
            if server.auth_state != state:
                print(f"❌ State parameter mismatch (possible CSRF attack)")
                return False
            
            self.log(f"Received authorization code: {server.auth_code[:20]}...")
            
            # Exchange authorization code for tokens
            return self.exchange_code_for_tokens(server.auth_code, code_verifier, actual_redirect_uri)
            
        except Exception as e:
            print(f"❌ Error during authentication flow: {e}")
            return False
        finally:
            try:
                server.shutdown()
            except:
                pass
    
    def exchange_code_for_tokens(self, auth_code, code_verifier, redirect_uri):
        """Exchange authorization code for access and refresh tokens"""
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'code': auth_code,
            'redirect_uri': redirect_uri,
            'code_verifier': code_verifier
        }
        
        self.log(f"Exchanging authorization code for tokens at: {self.token_endpoint}")
        
        try:
            response = requests.post(
                self.token_endpoint,
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=10
            )
            
            if response.status_code != 200:
                print(f"❌ Error: Token exchange failed with status {response.status_code}")
                print(f"Response: {response.text}")
                return False
            
            token_response = response.json()
            self.access_token = token_response.get('access_token')
            self.refresh_token = token_response.get('refresh_token')
            
            if not self.access_token:
                print(f"❌ Error: No access_token in response")
                return False
            
            expires_in = token_response.get('expires_in', 3600)
            self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)
            
            # Store tokens
            self.store_token()
            
            self.info(f"✅ OIDC tokens obtained successfully")
            self.log(f"Token expires at: {self.token_expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
            self.log(f"Has refresh token: {bool(self.refresh_token)}")
            return True
            
        except requests.RequestException as e:
            print(f"❌ Error: Failed to exchange authorization code: {e}")
            return False
    
    def refresh_access_token(self):
        """Refresh access token using refresh token"""
        if not self.refresh_token:
            return False
        
        token_data = {
            'grant_type': 'refresh_token',
            'client_id': self.client_id,
            'refresh_token': self.refresh_token
        }
        
        self.log(f"Refreshing access token at: {self.token_endpoint}")
        
        try:
            response = requests.post(
                self.token_endpoint,
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=10
            )
            
            if response.status_code != 200:
                self.log(f"Token refresh failed with status {response.status_code}")
                return False
            
            token_response = response.json()
            self.access_token = token_response.get('access_token')
            
            # Update refresh token if provided
            if 'refresh_token' in token_response:
                self.refresh_token = token_response['refresh_token']
            
            if not self.access_token:
                return False
            
            expires_in = token_response.get('expires_in', 3600)
            self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)
            
            # Store updated tokens
            self.store_token()
            
            self.log(f"Token refreshed, expires at: {self.token_expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
            return True
            
        except requests.RequestException as e:
            self.log(f"Failed to refresh token: {e}")
            return False
    
    def is_token_valid(self):
        """Check if current token is valid (exists and not expired)"""
        if not self.access_token:
            return False
        
        if self.token_expires_at and datetime.now() + timedelta(minutes=5) >= self.token_expires_at:
            return False
        
        return True
    
    def store_token(self):
        """Store tokens to file"""
        self.token_file.parent.mkdir(parents=True, exist_ok=True)
        
        token_data = {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'expires_at': self.token_expires_at.isoformat() if self.token_expires_at else None
        }
        
        try:
            with open(self.token_file, 'w') as f:
                json.dump(token_data, f, indent=2)
            
            os.chmod(self.token_file, 0o600)
            self.log(f"Tokens stored to: {self.token_file}")
            
        except Exception as e:
            print(f"⚠️  Warning: Failed to store tokens: {e}")
    
    def load_stored_token(self):
        """Load tokens from file"""
        if not self.token_file.exists():
            return False
        
        try:
            with open(self.token_file) as f:
                token_data = json.load(f)
            
            self.access_token = token_data.get('access_token')
            self.refresh_token = token_data.get('refresh_token')
            
            if token_data.get('expires_at'):
                self.token_expires_at = datetime.fromisoformat(token_data['expires_at'])
            
            self.log(f"Loaded tokens from: {self.token_file}")
            return bool(self.access_token)
            
        except Exception as e:
            self.log(f"Failed to load stored tokens: {e}")
            return False
    
    def call_registry_server(self, endpoint, payload, method='POST'):
        """Call the existing MCP registry server with bearer token"""
        if not self.access_token:
            print(f"❌ Error: No access token available")
            return False
        
        # Construct the full URL
        url = f"{self.registry_url}/{endpoint.lstrip('/')}"
        
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json',
            'User-Agent': 'MCP-Registry-Client-PKCE/1.0',
            'Accept': 'application/json'
        }
        
        self.log(f"Calling registry server: {method} {url}")
        self.log(f"Headers: {dict(headers)}")
        if payload:
            self.log(f"Payload: {json.dumps(payload, indent=2)}")
        
        try:
            if method.upper() == 'POST':
                response = requests.post(url, json=payload, headers=headers, timeout=30)
            elif method.upper() == 'PUT':
                response = requests.put(url, json=payload, headers=headers, timeout=30)
            elif method.upper() == 'GET':
                response = requests.get(url, headers=headers, timeout=30)
            else:
                print(f"❌ Error: Unsupported HTTP method: {method}")
                return False
            
            self.log(f"Response status: {response.status_code}")
            self.log(f"Response headers: {dict(response.headers)}")
            
            if response.status_code in [200, 201, 202]:
                self.info(f"✅ Successfully called registry server!")
                
                # Try to parse JSON response
                try:
                    response_data = response.json()
                    self.info(f"Server response: {json.dumps(response_data, indent=2)}")
                except json.JSONDecodeError:
                    self.info(f"Server response (text): {response.text}")
                
                return True
            else:
                print(f"❌ Error: Registry server returned status {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except requests.RequestException as e:
            print(f"❌ Error: Failed to call registry server: {e}")
            return False
    
    def publish_server(self, server_payload, endpoint='api/publish'):
        """Publish server to MCP registry via existing server"""
        self.info(f"Publishing server '{server_payload.get('name', 'unknown')}' to registry...")
        return self.call_registry_server(endpoint, server_payload, 'POST')
    
    def get_servers(self, endpoint='api/servers'):
        """Get list of servers from registry"""
        self.info("Fetching servers from registry...")
        return self.call_registry_server(endpoint, {}, 'GET')
    
    def publish_from_file(self, config_file_path, endpoint='api/publish'):
        """Load server config from file and publish"""
        try:
            with open(config_file_path, 'r') as f:
                server_payload = json.load(f)
            
            self.log(f"Loaded server config from: {config_file_path}")
            return self.publish_server(server_payload, endpoint)
            
        except Exception as e:
            print(f"❌ Error: Failed to load config file {config_file_path}: {e}")
            return False


def create_example_server_payload():
    """Create an example server payload for the registry"""
    return {
        "name": "my-awesome-mcp-server-pkce",
        "displayName": "My Awesome MCP Server (PKCE Auth)",
        "description": "An awesome MCP server authenticated with PKCE - no client secrets needed!",
        "version": "1.0.0",
        "author": {
            "name": "Your Name",
            "email": "you@example.com",
            "url": "https://github.com/yourusername"
        },
        "license": "MIT",
        "homepage": "https://github.com/yourusername/my-awesome-mcp-server",
        "repository": {
            "type": "git",
            "url": "https://github.com/yourusername/my-awesome-mcp-server.git"
        },
        "keywords": ["mcp", "server", "pkce", "secure-auth"],
        "categories": ["productivity", "development"],
        "capabilities": {
            "tools": [
                {
                    "name": "secure_operation",
                    "description": "Perform secure operations with PKCE authentication"
                }
            ],
            "resources": [
                {
                    "name": "protected_resources",
                    "description": "Access to protected resources via PKCE"
                }
            ]
        },
        "security": {
            "authentication": "PKCE",
            "requires_browser": True,
            "client_secret_required": False
        }
    }


def main():
    parser = argparse.ArgumentParser(
        description='Call MCP Registry server using OIDC PKCE authentication (no client secret)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Publish server with PKCE (no client secret needed)
  %(prog)s publish --registry https://registry.example.com \\
                   --issuer https://dex.example.com \\
                   --client-id mcp-public-client \\
                   --config server-config.json

  # Auto-detect from package.json
  %(prog)s publish --auto-detect

  # List servers  
  %(prog)s list

  # Use custom redirect port
  %(prog)s publish --port 9999 --example

  # Use environment variables
  export REGISTRY_URL=https://registry.example.com
  export OIDC_ISSUER_URL=https://dex.example.com  
  export OIDC_CLIENT_ID=mcp-public-client
  %(prog)s publish --config server-config.json
        """
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Publish command
    publish_parser = subparsers.add_parser('publish', help='Publish server to registry')
    publish_parser.add_argument('--config', '-c', type=Path, help='Server configuration file (JSON)')
    publish_parser.add_argument('--auto-detect', action='store_true', help='Auto-detect server config from package.json')
    publish_parser.add_argument('--example', action='store_true', help='Use example server configuration')
    publish_parser.add_argument('--endpoint', default='api/publish', help='Registry publish endpoint')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List servers from registry')
    list_parser.add_argument('--endpoint', default='api/servers', help='Registry list endpoint')
    
    # Common arguments for all commands
    for p in [publish_parser, list_parser]:
        # Registry configuration
        p.add_argument('--registry', default=os.getenv('REGISTRY_URL'), help='MCP Registry URL (env: REGISTRY_URL)')
        
        # OIDC Configuration  
        p.add_argument('--issuer', default=os.getenv('OIDC_ISSUER_URL'), help='OIDC issuer URL (env: OIDC_ISSUER_URL)')
        p.add_argument('--client-id', default=os.getenv('OIDC_CLIENT_ID', 'mcp-registry-client'), help='OIDC client ID - must be public client (env: OIDC_CLIENT_ID, default: mcp-registry-client)')
        
        # PKCE options
        p.add_argument('--port', type=int, default=8080, help='Local callback port for PKCE flow (default: 8080)')
        p.add_argument('--device-flow', action='store_true', help='Use device authorization flow (requires Dex support)')
        p.add_argument('--browser-flow', action='store_true', help='Force browser flow (requires local browser)')
        p.add_argument('--client-credentials', action='store_true', help='Use client credentials flow (requires OIDC_CLIENT_SECRET)')
        
        # Options
        p.add_argument('--scopes', default='openid,profile,email', help='Comma-separated list of scopes')
        p.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
        p.add_argument('--dry-run', action='store_true', help='Show what would be sent without actually doing it')
        p.add_argument('--force-auth', action='store_true', help='Force new authentication (ignore cached tokens)')
    
    args = parser.parse_args()
    
    # Default to publish if no command specified
    if not args.command:
        print("❌ Error: No command specified. Use 'publish' or 'list'")
        print("\nExamples:")
        print("  python3 mcp_reg_client.py publish --example")
        print("  python3 mcp_reg_client.py list")
        print("  python3 mcp_reg_client.py publish --config server.json")
        print("\nUse --help for more options")
        sys.exit(1)
    
    # Validate required arguments
    if not args.registry:
        print("❌ Error: --registry is required (or set REGISTRY_URL)")
        sys.exit(1)
    if not args.issuer:
        print("❌ Error: --issuer is required (or set OIDC_ISSUER_URL)")
        sys.exit(1)
    if not args.client_id:
        print("❌ Error: --client-id is required (or set OIDC_CLIENT_ID)")
        print("💡 Note: Use a PUBLIC client ID (no client secret required)")
        sys.exit(1)
    
    # Parse scopes
    scopes = [s.strip() for s in args.scopes.split(",")]
    
    # Create client
    client = MCPRegistryClient(
        args.registry, args.issuer, args.client_id, args.port, args.verbose
    )
    
    # Determine authentication flow
    use_device_flow = getattr(args, 'device_flow', False)
    use_client_credentials = getattr(args, 'client_credentials', False)
    
    if getattr(args, 'browser_flow', False):
        use_device_flow = False
        use_client_credentials = False
    elif use_client_credentials:
        client.info("🔑 Using client credentials flow (service account)")
    elif use_device_flow:
        client.info("🖥️  Using device authorization flow (may not be supported by Dex)")
    elif not use_device_flow and not use_client_credentials:
        # Auto-detect: use client credentials if secret available, otherwise browser
        if os.getenv('OIDC_CLIENT_SECRET'):
            use_client_credentials = True
            client.info("🔑 Auto-detected client credentials flow (found OIDC_CLIENT_SECRET)")
        else:
            client.info("🌐 Using browser-based PKCE flow")
    
    # Force re-authentication if requested
    if getattr(args, 'force_auth', False):
        if client.token_file.exists():
            client.token_file.unlink()
            client.info("🔄 Forced re-authentication - removed cached tokens")
    
    # Discover OIDC endpoints
    if not client.discover_oidc_endpoints():
        sys.exit(1)
    
    # Get access token using appropriate flow
    if not client.get_access_token_pkce(scopes, use_device_flow, use_client_credentials):
        sys.exit(1)
    
    # Execute command
    success = False
    
    if args.command == 'list':
        if args.dry_run:
            print(f"🔍 DRY RUN - Would call: GET {args.registry}/{args.endpoint}")
        else:
            success = client.get_servers(args.endpoint)
    
    elif args.command == 'publish':
        # Load server configuration (same logic as before)
        server_payload = None
        
        if args.example:
            server_payload = create_example_server_payload()
            print("📝 Using example server configuration with PKCE")
        elif args.config:
            pass
        elif args.auto_detect:
            # Try to load from package.json (same function as before)
            try:
                with open('package.json') as f:
                    pkg = json.load(f)
                server_payload = {
                    "name": pkg.get('name', 'unknown'),
                    "description": pkg.get('description', ''),
                    "version": pkg.get('version', '1.0.0'),
                    "author": pkg.get('author', ''),
                    "license": pkg.get('license', ''),
                    "security": {"authentication": "PKCE"}
                }
                print("📦 Auto-detected server configuration from package.json")
            except:
                print("❌ Error: Could not auto-detect configuration from package.json")
                sys.exit(1)
        else:
            print("❌ Error: No server configuration provided. Use --config, --auto-detect, or --example")
            sys.exit(1)
        
        # Dry run mode
        if args.dry_run:
            print("🔍 DRY RUN MODE - Would publish:")
            if server_payload:
                print(json.dumps(server_payload, indent=2))
            else:
                print(f"Configuration from file: {args.config}")
            print(f"To registry: {args.registry}/{args.endpoint}")
            return
        
        # Publish server
        if args.config:
            success = client.publish_from_file(args.config, args.endpoint)
        elif server_payload:
            success = client.publish_server(server_payload, args.endpoint)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
