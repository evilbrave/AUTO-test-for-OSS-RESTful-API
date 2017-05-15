import requests

import common_data
from signature import Signature
import test_1_device_auth
import time
url = common_data.oss_url
#url = "http://127.0.0.1:8888"
path = "/v1/domains"
test_time = time.time()

def init_headers(headers):
    headers['Content-Type'] = common_data.content_type
    headers['X-Api-Key'] = common_data.x_api_key
    headers['X-Signature'] = ""
    return headers

def init_body_content(body_content):
    body_content['certificate_serial'] = common_data.certificate_serial
    body_content['access_token'] = ""
    body_content['domain'] = "TEST_DOMAIN_"+str(test_time)
    body_content['domain'] = "TEST_DOMAIN"
    return body_content

def testcase_0(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 200 :
        print "TEST CASE 0 OK"
    else:
        print "TEST CASE 0 FAILED"
        print response.status_code
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text


def testcase_1(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    headers.pop('Content-Type')

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature
    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.23":
        print "TEST CASE 1 OK!"
    else:
        print "TEST CASE 1 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_2(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    headers.pop('X-Signature')

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.0":
        print "TEST CASE 2 OK!"
    else:
        print "TEST CASE 2 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_3(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    headers.pop('X-Api-Key')

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 403:# and response.json()['code'] == "400.0":
        print "TEST CASE 3 OK!"
    else:
        print response.status_code
        print "TEST CASE 3 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_4(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content.pop('certificate_serial')

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.2":
        print "TEST CASE 4 OK!"
    else:
        print "TEST CASE 4 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_5(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content.pop('access_token')

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.6":
        print "TEST CASE 5 OK!"
    else:
        print "TEST CASE 5 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_6(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content.pop('domain')

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.7":
        print "TEST CASE 6 OK!"
    else:
        print "TEST CASE 6 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_7(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    headers['Content-Type'] = "INVALID_CONTENT_TYPE"

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.19":
        print "TEST CASE 7 OK!"
    else:
        print response.status_code
        print "TEST CASE 7 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_8(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    headers['X-Signature'] = "INVALID_X_SIGNATURE"

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.1":
        print "TEST CASE 8 OK!"
    else:
        print response.status_code
        print "TEST CASE 8 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_9(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    headers['X-Api-Key'] = "INVALID_X_API_KEY"

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400:# and response.json()['code'] == "400.1":
        print "TEST CASE 9 OK!"
    else:
        print response.status_code
        print "TEST CASE 9 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_10(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content['certificate_serial'] = "INVALID_CERTIFICATE_SERIAL"

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.3":
        print "TEST CASE 10 OK!"
    else:
        print response.status_code
        print "TEST CASE 10 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_11(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content['access_token'] = "INVALID_ACCESS_TOKEN"

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "401.0":
        print "TEST CASE 11 OK!"
    else:
        print response.status_code
        print "TEST CASE 11 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_12(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content['domain'] = "INVALID_DOMAIN!"

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.8":
        print "TEST CASE 12 OK!"
    else:
        print response.status_code
        print "TEST CASE 12 FAILED!"
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

    testcase_0(headers, body_content)
    # testcase_1(headers, body_content)
    # testcase_2(headers, body_content)
    # testcase_3(headers, body_content)
    # testcase_4(headers, body_content)
    # testcase_5(headers, body_content)
    # testcase_6(headers, body_content)
    # testcase_7(headers, body_content)
    # testcase_8(headers, body_content)
    # testcase_9(headers, body_content)
    # testcase_10(headers, body_content)
    # testcase_11(headers, body_content)
    # testcase_12(headers, body_content)
    #test_create_domain(access_token['access_token'], new_domain)