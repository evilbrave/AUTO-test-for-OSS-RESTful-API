import requests
from signature import Signature
import common_data
import test_1_device_auth
from requests.utils import quote

url = common_data.oss_url
#url = "http://127.0.0.1:8888"
path = "/v1/domains/"

def init_headers(headers):
    headers['X-Api-Key'] = common_data.x_api_key
    headers['X-Signature'] = ""
    return headers

def init_body_content(body_content):
    body_content['certificate_serial'] = common_data.certificate_serial
    body_content['access_token'] = ""
    return body_content

def testcase_0(headers, body_content, domain):
    headers = headers.copy()
    body_content = body_content.copy()

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain, params=body_content, headers=headers)

    if response.status_code == 200 :
        print "TEST CASE 0 OK"
    else:
        print "TEST CASE 0 FAILED"
        print response.status_code
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_1(headers, body_content, domain):
    headers = headers.copy()
    body_content = body_content.copy()

    headers.pop('X-Api-Key')

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain, params=body_content, headers=headers)

    if response.status_code == 400 :#and response.json()['code'] == "400.0":
        print "TEST CASE 1 OK"
    else:
        print "TEST CASE 1 FAILED"
        print response.status_code
        print "HTTP Path: " + url + path + domain
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_2(headers, body_content, domain):
    headers = headers.copy()
    body_content = body_content.copy()

    headers.pop('X-Signature')

    response = requests.get(url + path + domain, params=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.0":
        print "TEST CASE 2 OK"
    else:
        print "TEST CASE 2 FAILED"
        print response.status_code
        print "HTTP Path: " + url + path + domain
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_3(headers, body_content, domain):
    headers = headers.copy()
    body_content = body_content.copy()

    domain = ""

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_text = common_data.get_concat_text(concat_dict)

    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain, params=body_content, headers=headers)

    if response.status_code == 400 :#and response.json()['code'] == "400.0":
        print "TEST CASE 3 OK"
    else:
        print "TEST CASE 3 FAILED"
        print response.status_code
        print "HTTP Path: " + url + path + domain
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

# no certificate serial
def testcase_4(headers, body_content, domain):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content.pop('certificate_serial')

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain, params=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.2":
        print "TEST CASE 4 OK"
    else:
        print "TEST CASE 4 FAILED"
        print response.status_code
        print "HTTP Path: " + url + path + domain
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

# no access token
def testcase_5(headers, body_content, domain):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content.pop('access_token')

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain, params=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.6":
        print "TEST CASE 5 OK"
    else:
        print "TEST CASE 5 FAILED"
        print response.status_code
        print "HTTP Path: " + url + path + domain
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

# invalid x-api-key
def testcase_6(headers, body_content, domain):
    headers = headers.copy()
    body_content = body_content.copy()

    headers['X-Api-Key'] = "INVALID_X_API_KEY"

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain, params=body_content, headers=headers)

    if response.status_code == 400:# and response.json()['code'] == "400.6":
        print "TEST CASE 6 OK"
    else:
        print "TEST CASE 6 FAILED"
        print response.status_code
        print "HTTP Path: " + url + path + domain
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

# invalid x-signature
def testcase_7(headers, body_content, domain):
    headers = headers.copy()
    body_content = body_content.copy()

    headers['X-Signature'] = "INVALID_X_SIGNATURE"

    response = requests.get(url + path + domain, params=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.1":
        print "TEST CASE 7 OK"
    else:
        print "TEST CASE 7 FAILED"
        print response.status_code
        print "HTTP Path: " + url + path + domain
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

# invalid domain
def testcase_8(headers, body_content, domain):
    headers = headers.copy()
    body_content = body_content.copy()

    domain = "INVALID_DOMAIN@"

    concat_dict = body_content.copy()
    concat_dict['domain'] = quote(domain)
    concat_text = common_data.get_concat_text(concat_dict)
    print concat_text
    concat_text = body_content['access_token'] + body_content['certificate_serial'] + "INVALID_DOMAIN@"
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    print signed_signature
    headers['X-Signature'] = signed_signature



    print quote(domain)
    response = requests.get(url + path + quote(domain), params=body_content, headers=headers)

    if response.status_code == 400:# and response.json()['code'] == "400.6":
        print "TEST CASE 8 OK"
    else:
        print "TEST CASE 8 FAILED"
        print response.status_code
        print "HTTP Path: " + url + path + domain
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

# invalid certificate serial
def testcase_9(headers, body_content, domain):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content['certificate_serial'] = "INVALID_CERTIFICATE_SERIAL"

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain, params=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.3":
        print "TEST CASE 9 OK"
    else:
        print "TEST CASE 9 FAILED"
        print response.status_code
        print "HTTP Path: " + url + path + domain
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

# invalid access_token
def testcase_10(headers, body_content, domain):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content['access_token'] = "INVALID_ACCESS_TOKEN"

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain, params=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "401.0":
        print "TEST CASE 10 OK"
    else:
        print "TEST CASE 10 FAILED"
        print response.status_code
        print "HTTP Path: " + url + path + domain
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

if __name__ == '__main__':

    # set headers
    headers = dict()
    headers = init_headers(headers)

    # set body
    body_content = dict()
    init_body_content(body_content)

    sso_tokens = test_1_device_auth.get_device_authentication_token()
    if sso_tokens.has_key('access_token') and sso_tokens.has_key('refresh_token'):
        body_content['access_token'] = sso_tokens['access_token']
    else:
        print "[Error] init access token failed!"
        exit(-1)

    domain = "TEST_DOMAIN"

    testcase_0(headers, body_content, domain)
    # testcase_1(headers, body_content, domain)
    # testcase_2(headers, body_content, domain)
    # testcase_3(headers, body_content, domain)
    # testcase_4(headers, body_content, domain)
    # testcase_5(headers, body_content, domain)
    # testcase_6(headers, body_content, domain)
    # testcase_7(headers, body_content, domain)
    # testcase_8(headers, body_content, domain)
    # testcase_9(headers, body_content, domain)
    # testcase_10(headers, body_content, domain)