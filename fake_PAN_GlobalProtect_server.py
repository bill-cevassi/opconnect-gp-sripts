#!/usr/bin/env python3

# This is used for testing openconnect's (https://github.com/dlenski/openconnect).
# handling of the atrocious XML+JavaScript mess used for
# authenticating to a PAN GlobalProtect VPN.
#
# Requires a recent version of Flask and Python 3.x, and a server.pem
#
# Should be fairly easy to tweak to fit various authentication scenarios.

import ssl
import hashlib
import random
from flask import Flask, request, abort

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('server.pem')

app = Flask(__name__)
app.config.update(
    PORT = 4443,
    HOST = 'localhost',
    USER = 'nobody',
    PASS = 'nothing',
    CHALLENGE = ''.join(random.choice('abcdef0123456789') for x in range(4)),
    TOKEN = ''.join(random.choice('0123456789') for x in range(6)),
    AUTHCOOKIE = hashlib.md5(bytes(random.randint(0,10))).hexdigest(),
)

@app.route('/global-protect/getconfig.esp', methods=('POST',))
def portal_config():
    user = request.form['user']
    passwd = request.form['passwd'] 
    inputStr = request.form.get('inputStr', '')
    if user == app.config['USER'] and passwd == app.config['PASS'] and inputStr == '':
        if random.randint(0,1):
            return '''
            var respStatus = "Challenge";
            var respMsg = "JavaScript sez: Enter your token code ({})";
            thisForm.inputStr.value = "{}";
            '''.format(app.config['TOKEN'], app.config['CHALLENGE'])
        else:
            return '''<challenge>
	    <user>{}</user>
	    <inputstr>{}</inputstr>
	    <respmsg>XML sez: Enter your token code ({})</respmsg>
            </challenge>'''.format(app.config['USER'], app.config['CHALLENGE'], app.config['TOKEN'])

    elif user == app.config['USER'] and passwd == app.config['TOKEN'] and inputStr == app.config['CHALLENGE']:
        # condensed portal XML
        return '''<?xml version="1.0" encoding="UTF-8" ?>
            <policy><gateways><external><list><entry name="{}:{}">
            <priority>1</priority>
            <manual>yes</manual>
            <description>TestGateway</description>
            </entry></list></external></gateways></policy>'''.format(app.config['HOST'], app.config['PORT'])
    else:
        return 'Invalid username or password', 512

@app.route('/ssl-vpn/login.esp', methods=('POST',))
def gateway_login():
    user = request.form['user']
    passwd = request.form['passwd']
    inputStr = request.form.get('inputStr', '')
    if user == app.config['USER'] and passwd == app.config['PASS']:
        return '''<?xml version="1.0" encoding="utf-8"?> <jnlp> <application-desc>
            <argument>(null)</argument>
            <argument>{}</argument>
            <argument>deadbeefdeadbeefdeadbeefdeadbeefdeadbeef</argument>
            <argument>TestGateway</argument>
            <argument>{}</argument>
            <argument>TestAuth</argument>
            <argument>vsys1</argument>
            <argument>TestDomain</argument>
            <argument>(null)</argument>
            <argument></argument>
            <argument></argument>
            <argument></argument>
            <argument>tunnel</argument>
            <argument>-1</argument>
            <argument>4100</argument>
            <argument></argument>
            <argument></argument>
            <argument></argument>
            </application-desc></jnlp>'''.format(app.config['AUTHCOOKIE'], app.config['USER'])
    else:
        return 'Invalid username or password', 512

@app.errorhandler(512)
def baduserpass(error):
    return 'Invalid username or password'
        
app.run(host=app.config['HOST'], port=app.config['PORT'], debug=True, ssl_context=context)
