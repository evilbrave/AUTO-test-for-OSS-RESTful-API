import requests

import common_data
from signature import Signature
import test_1_device_auth
import time
url = common_data.oss_url
#url = "http://127.0.0.1:8888"
path = "/v1/domains/"
test_time = time.time()

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

    body_content['domain'] = domain
    concat_text = common_data.get_concat_text(body_content)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.delete(url + path + domain, params=body_content, headers=headers)

    if response.status_code == 200 :
        print "TEST CASE 0 OK"
    else:
        print "TEST CASE 0 FAILED"
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
    delete_domain = "TEST_DOMAIN_1493804861.42"
    testcase_0(headers, body_content, delete_domain)
