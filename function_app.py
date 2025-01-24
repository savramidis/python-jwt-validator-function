import azure.functions as func
import logging

from jwt_validation_decorator import validate_jwt_decorator

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.function_name(name="jwt_validator")
@app.route(route="jwt_validator")
@validate_jwt_decorator
def jwt_validator(req: func.HttpRequest) -> func.HttpResponse:
    """
    JWTValidator is an asynchronous HTTP trigger function that processes a request and returns a personalized response.
    Args:
        req (func.HttpRequest): The HTTP request object.
    Returns:
        func.HttpResponse: The HTTP response object containing a personalized message if a name is provided in the query string or request body, otherwise a generic message.
    The function attempts to retrieve the 'name' parameter from the query string. If not found, it tries to parse the request body as JSON to get the 'name' parameter. Depending on whether the 'name' parameter is found, it returns a personalized greeting or a generic message.
    """
    logging.info('Python HTTP trigger function processed a request.')

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    if name:
        return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
             status_code=200
        )