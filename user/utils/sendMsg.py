import requests
import json
import logging
from flask import jsonify


def send_sms(mobile, content, sign='【牛盾网络】'):
    url = 'http://smsapi.newdun.net/send.php?appKey=2xKaOWK9NEcotcO7&appSecret=yQELEbzRhLbShaSWa0zLtybOHiTYAw9Y&mobiles=%s&content=%s&sign=%s' % (
        mobile, content, sign)

    try:
        response = requests.get(url)
        text = response.text
    except Exception as e:
        logging.error(e)
        return jsonify(message=e)

    json_data = {}
    json_data['code'] = json.loads(text)['code']
    json_data['msg'] = json.loads(text)['msg']

    json_str = json.dumps(json_data)

    return json_str


# if __name__ == '__main__':
#     send_sms('18855998210', '您的验证码是：333333')
