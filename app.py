from flask import Flask, render_template, redirect, request, Response
from flask_bootstrap import Bootstrap
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import adal
import Cookie
import json
import sys
import os
import random
import boto3
import string
import jwt

# https://login.microsoftonline.com/common/discovery/keys
# https://login.microsoftonline.com/tenant/.well-known/openid-configuration

parameters_file = (sys.argv[1] if len(sys.argv) == 2 else
                   os.getcwd() + '/ADAL_PARAMETERS')

if parameters_file:
    with open(parameters_file, 'r') as f:
        parameters = f.read()
    adal_parameters = json.loads(parameters)
else:
    raise ValueError('Please provide parameter file with account information.')

TEMPLATE_AUTHZ_URL = ('https://login.windows.net/{}/oauth2/authorize?' +
                      'response_type=id_token+code&response_mode=form_post&client_id={}&redirect_uri={}&' +
                      'state={}&nonce={}&resource={}')

app = Flask(__name__)
Bootstrap(app)


def validate_id_token(id_token):
    try:
        f = open(adal_parameters['idp_cert'], 'r')
        cert_str = f.read()
        f.close()
    except IOError as e:
        print('Unable to open PEM certificate')
        return False

    cert_obj = load_pem_x509_certificate(cert_str, default_backend())
    public_key = cert_obj.public_key()

    try:
        token = jwt.decode(id_token,
                           public_key,
                           algorithms=['RS256'],
                           audience=adal_parameters['clientId'])
    except Exception as e:
        return False

    return True


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/login')
def login():
    auth_state = (''.join(random.SystemRandom()
                          .choice(string.ascii_uppercase + string.digits)
                          for _ in range(48)))

    nonce = auth_state
    cookie = Cookie.SimpleCookie()
    cookie['auth_state'] = auth_state
    authorization_url = TEMPLATE_AUTHZ_URL.format(
        adal_parameters['tenant'],
        adal_parameters['clientId'],
        adal_parameters['redirect_uri'],
        auth_state,
        nonce,
        adal_parameters['resource'])

    redirect_to_AAD = redirect(authorization_url)
    response = app.make_response(redirect_to_AAD)
    response.set_cookie('auth_state', auth_state)
    return response


@app.route('/login/callback', methods=['GET', 'POST'])
def login_callback():
    # Verify AAD id_token
    id_token = request.form['id_token']
    code = request.form['code']

    if id_token:
        if validate_id_token(id_token):
            is_authenticated = True
        else:
            is_authenticated = False
            return Response(json.dumps({'auth': 'error: invalid token'}), mimetype='application/json')
    else:
        return Response(json.dumps({'auth': 'error: no token found'}), mimetype='application/json')

    # Acquire AAD access_token for Graph API
    authority_url = (adal_parameters['authorityHostUrl'] + '/' +
                     adal_parameters['tenant'])

    context = adal.AuthenticationContext(authority_url)
    access_token = context.acquire_token_with_authorization_code(
        code,
        adal_parameters['redirect_uri'],
        adal_parameters['resource'],
        adal_parameters['clientId'],
        adal_parameters['clientSecret'])

    # Get list of Roles
    client = boto3.client('iam')
    iam_response = client.list_roles()
    roles_list = iam_response['Roles']
    roles = []
    for role in roles_list:
        roles.append(role['Arn'])

    # Get temporary AWS credentials using STS
    client = boto3.client('sts')

    aws_response = client.assume_role_with_web_identity(RoleArn='arn:aws:iam::062988484893:role/adminapi',
                                                        RoleSessionName='test',
                                                        WebIdentityToken=id_token)
    aws_creds = aws_response['Credentials'].values()

    auth_data = {}
    auth_data['id_token'] = id_token
    auth_data['access_token'] = access_token
    auth_data['aws_roles'] = roles
    auth_data['aws_accessKeyId'] = aws_creds[3]
    auth_data['aws_secretAccessKey'] = aws_creds[0]
    auth_data['aws_securityToken'] = aws_creds[1]

    return Response(json.dumps(auth_data), mimetype='application/json')
