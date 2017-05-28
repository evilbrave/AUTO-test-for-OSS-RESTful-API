from urllib import quote

import test_1_device_auth
import common_data
from signature import Signature
import requests

url = common_data.oss_url
# url = "http://127.0.0.1:8888"
path = "/v1/objects/"

def init_headers(headers):
    headers['X-Api-Key'] = common_data.x_api_key
    headers['X-Signature'] = ""
    return headers

def init_body_content(body_content):
    body_content['certificate_serial'] = common_data.certificate_serial
    body_content['access_token'] = ""
    return body_content

def testcase_0(headers, body_content, domain, key):
    headers = headers.copy()
    body_content = body_content.copy()

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_dict['key'] = key
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain + "/" + key, params=body_content, headers=headers)

    #response = requests.get(url + path + domain +"/" + key, params=body_content, headers=headers, allow_redirects=False)

    if response.status_code == 200 :
        print "TEST CASE 0 OK"
    else:
        print "TEST CASE 0 FAILED"
        print response.status_code
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_1(headers, body_content, domain, key):
    headers = headers.copy()
    body_content = body_content.copy()

    headers.pop('X-Api-Key')

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_dict['key'] = key
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain + "/" + key, params=body_content, headers=headers)

    #response = requests.get(url + path + domain +"/" + key, params=body_content, headers=headers, allow_redirects=False)

    # TODO check error code
    if response.status_code == 200 :
        print "TEST CASE 1 OK"
    else:
        print "TEST CASE 1 FAILED"
        print response.status_code
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_2(headers, body_content, domain, key):
    headers = headers.copy()
    body_content = body_content.copy()

    headers.pop('X-Signature')

    response = requests.get(url + path + domain + "/" + key, params=body_content, headers=headers)

    #response = requests.get(url + path + domain +"/" + key, params=body_content, headers=headers, allow_redirects=False)

    if response.status_code == 400 and response.json()['code'] == "400.0":
        print "TEST CASE 2 OK"
    else:
        print "TEST CASE 2 FAILED"
        print response.status_code
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_3(headers, body_content, domain, key):
    headers = headers.copy()
    body_content = body_content.copy()

    domain = ""

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_dict['key'] = key
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain + "/" + key, params=body_content, headers=headers)

    #response = requests.get(url + path + domain +"/" + key, params=body_content, headers=headers, allow_redirects=False)

    # TODO check error code
    if response.status_code == 400 and response.json()['code'] == "400.0":
        print "TEST CASE 3 OK"
    else:
        print "TEST CASE 3 FAILED"
        print response.status_code
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_4(headers, body_content, domain, key):
    headers = headers.copy()
    body_content = body_content.copy()

    key = ""

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_dict['key'] = key
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain + "/" + key, params=body_content, headers=headers)

    #response = requests.get(url + path + domain +"/" + key, params=body_content, headers=headers, allow_redirects=False)

    # TODO check error code
    if response.status_code == 400 and response.json()['code'] == "400.0":
        print "TEST CASE 4 OK"
    else:
        print "TEST CASE 4 FAILED"
        print response.status_code
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_5(headers, body_content, domain, key):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content.pop('certificate_serial')

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_dict['key'] = key
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain + "/" + key, params=body_content, headers=headers)

    #response = requests.get(url + path + domain +"/" + key, params=body_content, headers=headers, allow_redirects=False)

    if response.status_code == 400 and response.json()['code'] == "400.2":
        print "TEST CASE 5 OK"
    else:
        print "TEST CASE 5 FAILED"
        print response.status_code
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_6(headers, body_content, domain, key):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content.pop('access_token')

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_dict['key'] = key
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain + "/" + key, params=body_content, headers=headers)

    #response = requests.get(url + path + domain +"/" + key, params=body_content, headers=headers, allow_redirects=False)

    if response.status_code == 400 and response.json()['code'] == "400.6":
        print "TEST CASE 6 OK"
    else:
        print "TEST CASE 6 FAILED"
        print response.status_code
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_7(headers, body_content, domain, key):
    headers = headers.copy()
    body_content = body_content.copy()

    headers['X-Api-Key'] = "INVALID_X_API_KEY"

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_dict['key'] = key
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain + "/" + key, params=body_content, headers=headers)

    #response = requests.get(url + path + domain +"/" + key, params=body_content, headers=headers, allow_redirects=False)

    if response.status_code == 400 and response.json()['code'] == "400.6":
        print "TEST CASE 7 OK"
    else:
        print "TEST CASE 7 FAILED"
        print response.status_code
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_8(headers, body_content, domain, key):
    headers = headers.copy()
    body_content = body_content.copy()

    headers['X-Signature'] = "INVALID_X_SIGNATURE"

    response = requests.get(url + path + domain + "/" + key, params=body_content, headers=headers)

    #response = requests.get(url + path + domain +"/" + key, params=body_content, headers=headers, allow_redirects=False)

    if response.status_code == 400 and response.json()['code'] == "400.1":
        print "TEST CASE 8 OK"
    else:
        print "TEST CASE 8 FAILED"
        print response.status_code
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_9(headers, body_content, domain, key):
    headers = headers.copy()
    body_content = body_content.copy()

    domain = quote(domain+"###@@@@")

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_dict['key'] = key
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain + "/" + key, params=body_content, headers=headers)

    #response = requests.get(url + path + domain +"/" + key, params=body_content, headers=headers, allow_redirects=False)

    if response.status_code == 400 and response.json()['code'] == "400.6":
        print "TEST CASE 9 OK"
    else:
        print "TEST CASE 9 FAILED"
        print response.status_code
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_10(headers, body_content, domain, key):
    headers = headers.copy()
    body_content = body_content.copy()

    key = quote(key+"###@@@@")

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_dict['key'] = key
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain + "/" + key, params=body_content, headers=headers)

    #response = requests.get(url + path + domain +"/" + key, params=body_content, headers=headers, allow_redirects=False)

    if response.status_code == 400 and response.json()['code'] == "400.6":
        print "TEST CASE 10 OK"
    else:
        print "TEST CASE 10 FAILED"
        print response.status_code
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_11(headers, body_content, domain, key):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content['certificate_serial'] = "INVALID_CERTIFICATE_SERIAL"

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_dict['key'] = key
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain + "/" + key, params=body_content, headers=headers)

    #response = requests.get(url + path + domain +"/" + key, params=body_content, headers=headers, allow_redirects=False)

    if response.status_code == 400 and response.json()['code'] == "400.3":
        print "TEST CASE 11 OK"
    else:
        print "TEST CASE 11 FAILED"
        print response.status_code
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_12(headers, body_content, domain, key):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content['access_token'] = "INVALID_ACCESS_TOKEN"

    concat_dict = body_content.copy()
    concat_dict['domain'] = domain
    concat_dict['key'] = key
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.get(url + path + domain + "/" + key, params=body_content, headers=headers)

    #response = requests.get(url + path + domain +"/" + key, params=body_content, headers=headers, allow_redirects=False)

    if response.status_code == 401 and response.json()['code'] == "401.0":
        print "TEST CASE 12 OK"
    else:
        print "TEST CASE 12 FAILED"
        print response.status_code
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
    key = "TEST_KEY"

    testcase_0(headers, body_content, domain, key)
    # testcase_1(headers, body_content, domain, key)
    # testcase_2(headers, body_content, domain, key)
    # testcase_3(headers, body_content, domain, key)
    # testcase_4(headers, body_content, domain, key)
    # testcase_5(headers, body_content, domain, key)
    # testcase_6(headers, body_content, domain, key)
    # testcase_7(headers, body_content, domain, key)
    # testcase_8(headers, body_content, domain, key)
    # testcase_9(headers, body_content, domain, key)
    # testcase_10(headers, body_content, domain, key)
    # testcase_11(headers, body_content, domain, key)
    # testcase_12(headers, body_content, domain, key)
