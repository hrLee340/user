import config as conf
from utils import constants
from flask import jsonify
from itsdangerous import TimedJSONWebSignatureSerializer as tjs, SignatureExpired, BadSignature


class AuthToken(object):

    def generate_token(self, email):
        """
        生成token
        :param eamil:
        :return: token
        """
        serializer = tjs(conf.SECRET_KEY, expires_in=constants.VERIFY_EMAIL_TOKEN_EXPIRES)
        data = {
            'email': email
        }

        token = serializer.dumps(data).decode()

        return token

    def verify_auth_token(self, token):
        """
        验证token
        :param token:
        :return:data
        """
        serializer = tjs(conf.SECRET_KEY, expires_in=constants.VERIFY_EMAIL_TOKEN_EXPIRES)

        try:
            data = serializer.loads(token)

        except SignatureExpired:
            return jsonify(message='该链接已过期')  # valid token, but expired
        except BadSignature:
            return jsonify(message='链接异常')  # invalid token

        return data
