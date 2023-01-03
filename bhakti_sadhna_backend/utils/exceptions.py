from rest_framework.views import exception_handler

def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.

    handler = {
        'ValidationError' : custom_validation_error,
        'NotAuthenticated' : custom_authentication_error, 
        'InvalidToken' : custom_authentication_error
    }
    response = exception_handler(exc, context)


    if response is not None:
        pass
    execution_class = exc.__class__.__name__
    handler[execution_class](exc, context, response)
    
        
    return response
    



def custom_validation_error(exec, context, response):
    response.status_code = 200
    if response.data[list(response.data.keys())[0]][0].code== 'blank':
        msg = f'{str.title(list(response.data.keys())[0])} can not be blank'
    elif response.data[list(response.data.keys())[0]][0].code== 'required':
        msg = f'{str.title(list(response.data.keys())[0])} is required'
    elif response.data.keys():
        msg = response.data[list(response.data.keys())[0]][0]
    else:
        msg = response.data

    response.data = {
        'status' : False,
        'msg' : msg
    }
    return response



def custom_authentication_error(exec, context, response):
    response.status_code = 200
    msg = response.data

    response.data = {
        'status' : False,
        'msg' : msg
    }

    return response
