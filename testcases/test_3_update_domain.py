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
    headers['Content-Type'] = common_data.content_type
    headers['X-Api-Key'] = common_data.x_api_key
    headers['X-Signature'] = ""
    return headers

def init_body_content(body_content):
    body_content['certificate_serial'] = common_data.certificate_serial
    body_content['access_token'] = ""
    body_content['new_domain'] = ""

    return body_content

def testcase_0(headers, body_content, old_domain, new_domain):
    body_content['new_domain'] = new_domain
    headers = headers.copy()
    body_content = body_content.copy()

    concat_dict = body_content.copy()
    concat_dict['domain'] = old_domain
    concat_text = common_data.get_concat_text(concat_dict)
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    signed_signature = signature.sign(concat_text)
    headers['X-Signature'] = signed_signature

    response = requests.put(url + path + old_domain, data=body_content, headers=headers)

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

    old_domain = "TWF_DOMAIN"
    new_domain = "WTF_DOMAIN"
    testcase_0(headers, body_content, old_domain, new_domain)