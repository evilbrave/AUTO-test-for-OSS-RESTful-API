import requests
import common_data
from signature import Signature
import logging, sys

# set url
url = common_data.mycloud_url
# url = "http://127.0.0.1:8888"
path = "/d/oauth/authorize"


def get_device_authentication_token():
    headers = dict()
    headers = init_headers(headers)

    body_content = dict()
    init_body_content(body_content)
    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature
    response = response = requests.post(url + path, data=body_content, headers=headers)
    if response.status_code == 200:
        resp_data = response.json()
        if 'data' in resp_data and 'access_token' and 'refresh_token' in resp_data['data']:
            return resp_data['data']
        else:
            return {"access_token": "", "refresh_token": ""}
    else:
        return {"access_token": "", "refresh_token": ""}


def init_headers(headers):
    headers['Content-Type'] = common_data.content_type
    headers['X-Signature'] = ""
    return headers


def init_body_content(body_content):
    body_content['app_id'] = common_data.app_id
    body_content['certificate_serial'] = common_data.certificate_serial
    body_content['cloud_id'] = common_data.cloud_id
    body_content['mac_address'] = common_data.device_mac_addr
    body_content['serial_number'] = common_data.device_serial_number
    return body_content

# remove header Content-Type
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
        resp_data = response.json()
        if 'data' in resp_data and 'access_token' and 'refresh_token' in resp_data['data']:
            print "TEST CASE 0 OK"
        else:
            print "TEST CASE 0 FAILED"
            print "HTTP Header:" + str(headers)
            print "HTTP Body:" + str(body_content)
    else:
        print "TEST CASE 0 FAILED"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

# remove header Content-Type
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

    if response.status_code == 400 and response.json()['code'] == "400.18":
        print "TEST CASE 1 OK"
    else:
        print "TEST CASE 1 FAILED"
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

    body_content.pop('app_id')

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature
    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.4":
        print "TEST CASE 3 OK!"
    else:
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

    body_content.pop('cloud_id')

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.25":
        print "TEST CASE 5 OK!"
    else:
        print "TEST CASE 5 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text


def testcase_6(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content.pop('mac_address')

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.22":
        print "TEST CASE 6 OK!"
    else:
        print "TEST CASE 6 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_7(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content.pop('serial_number')

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.23":
        print "TEST CASE 7 OK!"
    else:
        print "TEST CASE 7 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)
    print response.text

def testcase_8(headers, body_content):
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
        print "TEST CASE 8 OK!"

    else:
        print "TEST CASE 8 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)

    print response.text

def testcase_9(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    headers['X-Signature'] = "INVALID_SIGNATURE"

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.1":
        print "TEST CASE 9 OK!"

    else:
        print "TEST CASE 9 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)

    print response.text

def testcase_10(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content['app_id'] = "INVALID_APP_ID"

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.5":
        print "TEST CASE 10 OK!"

    else:
        print "TEST CASE 10 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)

    print response.text

def testcase_11(headers, body_content):
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
        print "TEST CASE 11 OK!"

    else:
        print "TEST CASE 11 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)

    print response.text

def testcase_12(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content['cloud_id'] = "INVALID_CLOUD_ID"

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.26":
        print "TEST CASE 12 OK!"

    else:
        print "TEST CASE 12 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)

    print response.text

def testcase_13(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content['mac_address'] = "INVALID_MAC_ADDRESS"

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.24":
        print "TEST CASE 13 OK!"

    else:
        print "TEST CASE 13 FAILED!"
        print "HTTP Header:" + str(headers)
        print "HTTP Body:" + str(body_content)

    print response.text

def testcase_14(headers, body_content):
    headers = headers.copy()
    body_content = body_content.copy()

    body_content['serial_number'] = "INVALID_SERIAL_NUMBER"

    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.post(url + path, data=body_content, headers=headers)

    if response.status_code == 400 and response.json()['code'] == "400.24":
        print "TEST CASE 14 OK!"

    else:
        print "TEST CASE 14 FAILED!"
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

    # testcase_0(headers, body_content)

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
    # testcase_13(headers, body_content)
    testcase_14(headers, body_content)