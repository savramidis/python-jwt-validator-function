import jwt
import os
import re
import requests

from azure.functions import HttpRequest, HttpResponse
from functools import wraps
from jwt.algorithms import RSAAlgorithm


def remove_duplicate_slashes(url):
    """
    Removes duplicate slashes from a URL while preserving the protocol part.

    Args:
        url (str): The URL from which to remove duplicate slashes.

    Returns:
        str: The URL with duplicate slashes removed, preserving the protocol if present.

    Example:
        >>> remove_duplicate_slashes_preserve_protocol("http://example.com//foo//bar")
        'http://example.com/foo/bar'
        >>> remove_duplicate_slashes_preserve_protocol("example.com//foo//bar")
        'example.com/foo/bar'
    """
    # Split the URL into the protocol part and the rest
    parts = url.split("://", 1)
    if len(parts) == 2:
        # Process only the part after the protocol
        protocol = parts[0] + "://"
        path = re.sub(r'/+', '/', parts[1])
        return protocol + path
    else:
        # If no protocol is present, just remove duplicate slashes
        return re.sub(r'/+', '/', url)
    

def get_public_key(token, jwks=None):
    """
    Retrieves the public key for verifying a JWT token.
    Args:
        token (str): The JWT token for which the public key is needed.
        jwks (dict, optional): The JSON Web Key Set (JWKS) containing the keys. 
                               If not provided, it will be fetched from the JWKS_URI environment variable.
    Returns:
        RSAAlgorithm: The RSA public key corresponding to the token's key ID (kid).
    Raises:
        Exception: If the public key is not found in the JWKS.
    """
    if not jwks:
        # URL to fetch the JSON Web Key Set (JWKS) for verifying tokens
        jwks_uri = os.getenv('JWKS_URI')        
        if not jwks_uri:
            raise Exception("JWKS URI not found.")        
        jwks_uri = remove_duplicate_slashes(jwks_uri)
        jwks = requests.get(jwks_uri).json()
    
    header = jwt.get_unverified_header(token)

    for key in jwks['keys']:
        if key['kid'] == header['kid']:
            return RSAAlgorithm.from_jwk(key)
    raise Exception("Public key not found.")


def validate_jwt(jwt_to_validate, audience, issuer):
    """
    Validates a JSON Web Token (JWT) against the provided audience and issuer.
    Args:
        jwt_to_validate (str): The JWT string to be validated.
        audience (str): The expected audience of the JWT.
        issuer (str): The expected issuer of the JWT.
    Returns:
        dict: The decoded JWT payload if validation is successful.
    Raises:
        jwt.ExpiredSignatureError: If the JWT has expired.
        jwt.InvalidAudienceError: If the audience claim does not match.
        jwt.InvalidIssuerError: If the issuer claim does not match.
        jwt.InvalidTokenError: If the JWT is otherwise invalid.
    """
    public_key = get_public_key(jwt_to_validate)

    decoded = jwt.decode(jwt_to_validate,
                         public_key,
                         verify=True,
                         algorithms=['RS256'],
                         audience=audience,
                         issuer=issuer)    
    return decoded
        

def validate_jwt_decorator(f):
    """
    Decorator that ensures a valid JWT token is present in the request headers.
    Args:
        f (function): The function to be decorated.
    Returns:
        function: The decorated function that checks for a valid JWT token.
    Raises:
        HttpResponse: If the token is missing, expired, or invalid, an HTTP response with status code 401 is returned.
    Example:
        @jwt_required
        def my_decorated_func(req, *args, **kwargs):
            # Your logic here
    """
    @wraps(f)
    def decorated_function(req: HttpRequest, *args, **kwargs):                   
        try:            
            issuer = os.getenv('ISSUER')
            if not issuer:
                return HttpResponse("Issuer not found", status_code=401)
                        
            audience = os.getenv('AUDIENCE')
            if not audience:
                return HttpResponse("Audience not found", status_code=401)
            
            # Assuming the token is in the format "Bearer <token>"
            token = req.headers.get('Authorization')                
            if not token or not token.startswith("Bearer "):
                return HttpResponse("Missing or invalid token", status_code=401)
            
            token = token.split(" ")[1]
            decoded_token = validate_jwt(token, audience, issuer)
            print(decoded_token)
        except jwt.ExpiredSignatureError:
            return HttpResponse("Token has expired", status_code=401)
        except jwt.InvalidAudienceError:
            return HttpResponse("Invalid audience", status_code=401)
        except jwt.InvalidIssuerError:
            return HttpResponse("Invalid issuer", status_code=401)
        except jwt.InvalidTokenError as error:
            return HttpResponse(f"Invalid token: {str(error)}", status_code=401)
        except Exception as error:
            return HttpResponse(f"Error: {str(error)}", status_code=401)
        
        return f(req, *args, **kwargs)
    
    return decorated_function
