import random
import re
import logging
from flask import Blueprint, jsonify, session
from flask import request
from lib.mysql import *
from lib.redis import redis_store
from utils import constants, sendMsg, sendMail, emailCode
from utils.decorator import stat_called_time
from werkzeug.security import generate_password_hash, check_password_hash

BP = Blueprint('user', __name__, url_prefix='/user')

# 实例化mysql对象
db = MySql()


@BP.route('sms_code', methods=['POST'])
def sms_code():
    """
    发送验证码，保存redis
    :return:
    """

    # 获取数据
    json_data = request.json
    mobile = json_data.get('mobile')

    # 验证手机号是否合法
    if not re.match(r'^1[3456789][0-9]{9}$', mobile):
        return jsonify(message='手机号码有误')

    flag = redis_store.get('sms_flag_' + mobile)

    if flag:
        return jsonify(message='操作过于频繁，请稍后重试')

    # 发送短信操作
    sms_code_str = '%06d' % random.randint(0, 999999)

    try:
        pl = redis_store.pipeline()
        pl.setex('sms_code_' + mobile, constants.SMS_CODE_REDIS_EXPIRES, sms_code_str)
        pl.setex('sms_flag_' + mobile, constants.SEND_SMS_CODE_INTERVAL, 1)
        pl.execute()
    except Exception as e:
        logging.error(e)
        return jsonify(message="redis保存数据库错误")

    try:
        response = sendMsg.send_sms(mobile, '您的短信验证码是:%s' % sms_code_str)
        return response

    except Exception as e:
        logging.error(e)
        return jsonify(message='短信发送失败')


@BP.route('register', methods=['POST'])
def register():
    """
    注册
    :return:
    """
    # 获取前端数据
    mobile = request.json.get('mobile')
    sms_code = request.json.get('sms_code')
    password = request.json.get('password')

    # 验证数据完整性
    if not all([mobile, sms_code, password]):
        return jsonify(message='参数不全')

    # 密码长度验证
    if not re.match(r'^\w{6,20}$', password):
        return jsonify(message='密码长度为6-20个字符')

    # 判断是否注册
    sql = """select id from user where mobile=%s"""
    res, result = db.fetch_one(sql, mobile)

    if res:
        return jsonify(message="手机号已注册")

    # 对比短信验证码
    try:
        real_sms_code = redis_store.get('sms_code_' + mobile).decode()
    except Exception as e:
        logging.error(e)
        return jsonify(message="获取验证码错误")

    if not real_sms_code:
        return jsonify(message="短信验证码已过期")

    if real_sms_code != sms_code:
        return jsonify(message="验证码有误，请重新输入")

    try:
        redis_store.delete('sms_code_' + mobile)
    except Exception as e:
        logging.error(e)
        return jsonify(message="删除redis数据库错误")

    # 将密码进行加密
    password = generate_password_hash(password)

    # 将数据保存到数据库中
    sql = """insert into user (mobile, password) VALUES (%s, %s)"""

    db.insert(sql, (mobile, password))

    return jsonify(message='注册成功')


@BP.route('login', methods=['POST'])
def login():
    """
    登录
    :return:
    """
    # 获取前端数据
    json_data = request.json
    value = json_data.get('value')
    password = json_data.get('password')

    # 校验数据完整性
    if not all([value, password]):
        return jsonify(message='手机号或者密码不能为空')

    # 校验参数是否正确
    sql = """select id, mobile, email, password from user where mobile=%s or email=%s"""

    try:
        res, result = db.fetch_one(sql, (value, value))
    except Exception as e:
        logging.error(e)
        return jsonify(message='数据获取失败')

    if res == None:
        return jsonify(message='请先注册')

    if value == result[1] and check_password_hash(result[3], password):

        # 设置session
        session['value'] = value

        info = {
            'message': '登录成功',
            'value': value,
            'user_id': result[0]
        }

        return jsonify(info)

    elif value == result[2] and check_password_hash(result[3], password):

        # 设置session
        session['name'] = value

        info = {
            'message': '登录成功',
            'value': value,
            'user_id': result[0]
        }
        return jsonify(info)

    else:

        return jsonify(message='账号或密码有误，请重新输入')


@BP.route('mobile/login', methods=['POST'])
def mobile_login():
    """
    手机号登录
    :return:
    """
    # 获取参数
    mobile = request.json.get('mobile')
    code = request.json.get('code')

    if not all([mobile, code]):
        return jsonify(message='请填写手机号或验证码')

    # 判断是否注册
    sql = """select mobile from user where mobile=%s"""
    res, result = db.fetch_one(sql, mobile)

    if res == None:
        return jsonify(message='请先注册')

    # 对比短信验证码
    try:
        real_sms_code = redis_store.get('sms_code_' + mobile).decode()
    except Exception as e:
        logging.error(e)
        return jsonify(message="数据库错误")

    if not real_sms_code:
        return jsonify(message="短信验证码已过期")

    if real_sms_code != code:
        return jsonify(message="验证码填写错误")

    try:
        redis_store.delete('sms_code_' + mobile)
    except Exception as e:
        logging.error(e)
        return jsonify(message="删除redis数据库错误")

    # 设置session
    session['name'] = mobile

    # 返回用户信息
    sql = """select id, mobile from user where mobile=%s"""
    res, result = db.fetch_one(sql, mobile)

    return jsonify(id=result[0], mobile=result[1], message='登录成功')


@BP.route('set_name', methods=['POST'])
def set_name():
    """
    设置用户名
    :return:
    """
    # 获取前端数据
    id = request.json.get('id')
    name = request.json.get('name')

    # 验证数据
    if not name:
        return jsonify(message='用户名不能为空')

    if not re.match(r'^[\u4E00-\u9FA5A-Za-z0-9_]+$', name):
        return jsonify(message='用户名不合法')

    # 将用户名保存到数据库
    sql = """update user set name=%s where id=%s"""
    db.update(sql, (name, id))

    return jsonify(message='设置用户名成功')


@BP.route('set_mobile', methods=['POST'])
def set_mobile():
    """
    设置手机号(老用户使用邮箱登录，未绑定手机号)
    :return:
    """
    # 获取前端数据
    id = request.json.get('id')
    mobile = request.json.get('mobile')

    # 完整性判断
    if not mobile:
        return jsonify(message='手机号不能为空')

    # 对比短信验证码
    try:
        real_sms_code = redis_store.get('sms_code_' + mobile).decode()
    except Exception as e:
        logging.error(e)
        return jsonify(message="获取验证码错误")

    if not real_sms_code:
        return jsonify(message="短信验证码已过期")

    if real_sms_code != sms_code:
        return jsonify(message="验证码有误，请重新输入")

    try:
        redis_store.delete('sms_code_' + mobile)
    except Exception as e:
        logging.error(e)
        return jsonify(message="删除redis数据库错误")

    # 将手机号保存到数据库中
    sql = """update user set mobile=%s where id=%s"""
    db.update(sql, (mobile, id))

    return jsonify(message='手机号绑定成功')


@BP.route('email_code', methods=['POST'])
def email_code():
    """
    发送邮件验证码
    :return:
    """
    # 获取前端数据
    email = request.json.get('email')

    if not email:
        return jsonify(message='邮箱不能为空')

    # 邮箱验证
    if not re.match(r'^[0-9a-zA-Z_]{0,19}@[0-9a-zA-Z]{1,13}\.[com,cn,net]{1,3}$', email):
        return jsonify(message='请输入正确是邮箱地址')

    flag = redis_store.get('email_flag_' + email)

    if flag:
        return jsonify(message='操作过于频繁，请稍后重试')

    # 随机生成邮件验证码
    email_code = emailCode.generate_verification_code2()

    try:
        pl = redis_store.pipeline()
        pl.setex('email_code_' + email, constants.EMAIL_CODE_REDIS_EXPIRES, email_code)
        pl.setex('email_flag_' + email, constants.SEND_EMAIL_CODE_INTERVAL, 1)
        pl.execute()
    except Exception as e:
        logging.error(e)
        return jsonify(message="redis保存数据库错误")

    # 发送邮件
    html_message = '<p>尊敬的用户您好！</p>' \
                   '<p>您的验证码为:<p style="color:red;font-size:20px">%s</p>(该链接五分钟内有效，请及时验证)</p>' % (email_code)

    sendMail.SendMail(email, html_message)

    return jsonify(message='邮件发送成功，请查收')


@BP.route('set_email', methods=['POST'])
def set_email():
    """
    绑定邮箱
    :return:
    """
    # 获取数据
    id = request.json.get('id')
    email = request.json.get('email')
    email_code = request.json.get('email_code')

    # 对比邮箱验证码
    try:
        real_email_code = redis_store.get('email_code_' + email).decode()
    except Exception as e:
        logging.error(e)
        return jsonify(message="数据库错误")

    if not real_email_code:
        return jsonify(message="短信验证码已过期或者手机号填写错误")

    if real_email_code.lower() != email_code.lower():
        return jsonify(message="验证码填写错误")

    try:
        redis_store.delete('email_code_' + email)
    except Exception as e:
        logging.error(e)
        return jsonify(message="删除redis数据库错误")

    sql = """update user set email=%s where id=%s"""
    db.update(sql, (email, id))

    return jsonify(message='邮箱绑定成功')


@BP.route('check_mobile', methods=['POST'])
def check_mobile():
    """
    验证手机号，用于绑定新手机号
    :return:
    """
    # 获取前端数据
    mobile = request.json.get('mobile')
    sms_code = request.json.get('sms_code')

    # 对比短信验证码
    try:
        real_sms_code = redis_store.get('sms_code_' + mobile).decode()
    except Exception as e:
        logging.error(e)
        return jsonify(message="获取验证码错误")

    if not real_sms_code:
        return jsonify(message="短信验证码已过期")

    if real_sms_code != sms_code:
        return jsonify(message="验证码有误，请重新输入")

    try:
        redis_store.delete('sms_code_' + mobile)
    except Exception as e:
        logging.error(e)
        return jsonify(message="删除redis数据库错误")

    return jsonify(message='验证码验证成功')


@BP.route('reset_mobile', methods=['POST'])
def reset_mobile():
    """
    绑定新手机号
    :return:
    """
    # 获取前端数据
    id = request.json.get('id')
    new_mobile = request.json.get('new_mobile')
    sms_code = request.json.get('sms_code')

    if not all([new_mobile, sms_code]):
        return jsonify(message='手机号或验证码不能为空')

    # 检测新手机号是否注册
    sql = """select mobile from user where mobile=%s"""
    res, result = db.fetch_one(sql, new_mobile)

    if res:
        return jsonify(message='该手机号已注册')

    # 对比短信验证码
    try:
        real_sms_code = redis_store.get('sms_code_' + new_mobile).decode()
    except Exception as e:
        logging.error(e)
        return jsonify(message="获取验证码错误")

    if not real_sms_code:
        return jsonify(message="短信验证码已过期")

    if real_sms_code != sms_code:
        return jsonify(message="验证码有误，请重新输入")

    try:
        redis_store.delete('sms_code_' + new_mobile)
    except Exception as e:
        logging.error(e)
        return jsonify(message="删除redis数据库错误")

    # 保存新手机号
    sql = """update user set mobile=%s where id=%s"""

    db.update(sql, (new_mobile, id))

    return jsonify(message='修改手机号成功')


@BP.route('check_email', methods=['POST'])
def check_email():
    """
    验证邮箱(用于更换邮箱)
    :return:
    """
    email = request.json.get('email')
    email_code = request.json.get('email_code')

    # 对比邮箱验证码
    try:
        real_email_code = redis_store.get('email_code_' + email).decode()
    except Exception as e:
        logging.error(e)
        return jsonify(message="数据库错误")

    if not real_email_code:
        return jsonify(message="短信验证码已过期或者手机号填写错误")

    if real_email_code.lower() != email_code.lower():
        return jsonify(message="验证码填写错误")

    try:
        redis_store.delete('email_code_' + email)
    except Exception as e:
        logging.error(e)
        return jsonify(message="删除redis数据库错误")

    sql = """update user set email=%s where id=%s"""
    db.update(sql, (email, id))

    return jsonify(message='邮箱绑定成功')


@BP.route('reset_email', methods=['POST'])
def reset_email():
    """
    用户重置邮箱
    :return:
    """
    # 获取前端数据
    id = request.json.get('id')
    new_email = request.json.get('new_email')
    email_code = request.json.get('email_code')

    if not all([new_email, email_code]):
        return jsonify(message='手机号或验证码不能为空')

    # 对比邮件验证码
    try:
        real_email_code = redis_store.get('email_code_' + new_email).decode()
    except Exception as e:
        logging.error(e)
        return jsonify(message="获取验证码错误")

    if not real_email_code:
        return jsonify(message="短信验证码已过期")

    if real_email_code.lower() != email_code.lower():
        return jsonify(message="验证码有误，请重新输入")

    try:
        redis_store.delete('email_code_' + new_email)
    except Exception as e:
        logging.error(e)
        return jsonify(message="删除redis数据库错误")

    # 保存新手机号
    sql = """update user set email=%s where id=%s"""

    db.update(sql, (new_email, id))

    return jsonify(message='修改手机号成功')


@BP.route('pass_info', methods=['POST', 'GET'])
def pass_info():
    """
    修改密码
    :return:
    """

    # 获取参数
    mobile = request.json.get('mobile')
    sms_code = request.json.get('sms_code')
    new_password = request.json.get('new_password')

    # 验证参数
    if not all([mobile, sms_code, new_password]):
        return jsonify(message='参数不全')

    # 对比短信验证码
    try:
        real_sms_code = redis_store.get('sms_code_' + mobile).decode()
    except Exception as e:
        logging.error(e)
        return jsonify(message="获取验证码错误")

    if not real_sms_code:
        return jsonify(message="短信验证码已过期")

    if real_sms_code != sms_code:
        return jsonify(message="验证码有误，请重新输入")

    try:
        redis_store.delete('sms_code_' + mobile)
    except Exception as e:
        logging.error(e)
        return jsonify(message="删除redis数据库错误")

    # 将新密码加密插入数据库中
    new_password = generate_password_hash(new_password)

    sql = """update user set password=%s where mobile=%s"""
    db.update(sql, (new_password, mobile))

    return jsonify(message='修改密码成功')


@BP.route('logout', methods=['POST', 'GET'])
def logout():

    # 删除session信息
    session.pop('name', None)

    return jsonify(message='注销成功')

# @BP.route('register', methods=['POST'])
# def register():
#
#     # 获取前端数据
#     json_data = request.json
#     name = json_data.get('name')
#     mobile = json_data.get('mobile')
#     email = json_data.get('email')
#     password = json_data.get('password')
#     sms_code = json_data.get('sms_code')
#
#     # 验证数据完整性
#     if not all([name, mobile, email, password, sms_code]):
#         return jsonify(message='参数不全')
#
#     # 用户名验证
#     if not re.match(r"^[a-zA-Z]\w{6,18}", name):
#         return jsonify(message='用户名不合法')
#
#     # 邮箱验证
#     if not re.match(r'^[0-9a-zA-Z_]{0,19}@[0-9a-zA-Z]{1,13}\.[com,cn,net]{1,3}$', email):
#         return jsonify(message='请输入正确是邮箱地址')
#
#     # 判断是否注册
#     sql = """select id from user where mobile=%s"""
#     res, result = db.fetch_one(sql, mobile)
#
#     if res:
#         return jsonify(message="手机号已注册")
#
#     # 对比短信验证码
#     try:
#         real_sms_code = redis_store.get('sms_code_' + mobile).decode()
#     except Exception as e:
#         logging.error(e)
#         return jsonify(message="数据库错误")
#
#     if not real_sms_code:
#         return jsonify(message="短信验证码已过期或者手机号填写错误")
#
#     if real_sms_code != sms_code:
#         return jsonify(message="验证码填写错误")
#
#     try:
#         redis_store.delete('sms_code_' + mobile)
#     except Exception as e:
#         logging.error(e)
#         return jsonify(message="删除redis数据库错误")
#
#     # 将密码进行加密
#     password = generate_password_hash(password)
#
#     # 将数据保存到数据库中
#     sql = """insert into user (name, mobile, email, password) VALUES (%s, %s, %s, %s)"""
#
#     db.insert(sql, (name, mobile, email, password))
#
#     return jsonify(message='注册成功')
#
#
# @BP.route('login', methods=['POST'])
# @stat_called_time
# def login():
#
#     # 获取前端数据
#     json_data = request.json
#     name = json_data.get('name')
#     password = json_data.get('password')
#
#     # 校验数据完整性
#     if not all([name, password]):
#         return jsonify(message='用户名或者密码不能为空')
#
#     # 校验参数是否正确
#     sql = """select name, mobile, email, password from user where name=%s or mobile=%s or email=%s"""
#
#     try:
#         res, result = db.fetch_one(sql, (name, name, name))
#     except Exception as e:
#         logging.error(e)
#         return jsonify(message='查询数据失败')
#
#     if result == None:
#         return jsonify(message='用户名或密码不正确')
#
#     if name == result[0] and check_password_hash(result[3], password):
#
#         # 设置session
#         session['name'] = name
#         return jsonify(message='登录成功')
#
#     elif name == result[1] and check_password_hash(result[3], password):
#
#         # 设置session
#         session['name'] = name
#         return jsonify(message='登录成功')
#
#     elif name == result[2] and check_password_hash(result[3], password):
#
#         # 设置session
#         session['name'] = name
#         return jsonify(message='登录成功')
#
#     else:
#
#         return jsonify(message='请输入正确的用户名或密码')
#
#
# @BP.route('mobile/login', methods=['POST'])
# @stat_called_time
# def mobile_login():
#
#     # 获取参数
#     mobile = request.json.get('mobile')
#     code = request.json.get('code')
#
#     if not all([mobile, code]):
#         return jsonify(message='请填写手机号或验证码')
#
#     # 判断是否注册
#     sql = """select mobile from user where mobile=%s"""
#     res, result = db.fetch_one(sql, mobile)
#
#     if not res:
#         return jsonify(message='请先注册')
#
#     # 对比短信验证码
#     try:
#         real_sms_code = redis_store.get('sms_code_' + mobile).decode()
#     except Exception as e:
#         logging.error(e)
#         return jsonify(message="数据库错误")
#
#     if not real_sms_code:
#         return jsonify(message="短信验证码已过期或者手机号填写错误")
#
#     if real_sms_code != code:
#         return jsonify(message="验证码填写错误")
#
#     try:
#         redis_store.delete('sms_code_' + mobile)
#     except Exception as e:
#         logging.error(e)
#         return jsonify(message="删除redis数据库错误")
#
#     return jsonify(message='登录成功')
#
#
# @BP.route('image_code', methods=['POST'])
# def get_image_code():
#     ip = request.remote_addr
#     json_data = request.json
#     image_code = json_data.get('image_code')
#
#     if not image_code:
#         return jsonify(message='请输入验证码')
#
#     # 从redis中获取图片验证码
#     real_image_code = redis_store.get('ip_' + ip).decode()
#
#     if real_image_code.lower() != image_code.lower():
#         return jsonify(message='请输入正确的验证码')
#
#     try:
#         redis_store.delete('ip_' + ip)
#     except Exception as e:
#         logging.error(e)
#         return jsonify(message="删除redis数据库错误")
#
#     return jsonify(message='验证码正确')
#
#
# @BP.route('pass_info', methods=['POST', 'GET'])
# def modify_password():
#
#     # 获取参数
#     user_id = request.json.get('id')
#     old_password = request.json.get('old_password')
#     new_password = request.json.get('new_password')
#     new_password_again = request.json.get('new_password_again')
#
#
#     # 验证参数
#     if not all([old_password, new_password, new_password_again]):
#         return jsonify(message='参数不全')
#
#     # 校验原始密码
#     sql = """select password from user where id=%s"""
#
#     try:
#         res, result = db.fetch_one(sql, user_id)
#     except Exception as e:
#         logging.error(e)
#         return jsonify(message='查询数据失败')
#
#     if old_password != check_password_hash(result[0], old_password):
#         return jsonify(message='请输入正确的原始密码')
#
#     if new_password != new_password_again:
#         return jsonify(message='两次输入的密码不一致')
#
#     # 将新密码加密插入数据库中
#     new_password = generate_password_hash(new_password)
#
#     sql = """update user set password=%s where id=%s"""
#     db.update(sql, (new_password, user_id))
#
#     return jsonify(message='修改密码成功')
#
#
# @BP.route('forget_pass', methods=['POST', 'GET'])
# def forget_pass():
#
#     # 获取用户邮箱
#     global email
#     email = request.json.get('email')
#
#     # 校验邮箱
#     if not email:
#         return jsonify(message='请输入邮箱信息')
#
#     sql = """select email from user where email=%s"""
#     res, result = db.fetch_one(sql, email)
#
#     if res == None:
#         return jsonify(message='请输入注册时邮箱')
#
#     # 生成token值
#     token = AuthToken().generate_token(email)
#
#     # 保存数据库
#     sql = """update user set reset_password_token=%s where email=%s"""
#     db.update(sql, (token, email))
#
#     # 发送邮件
#     verify_url = 'http://127.0.0.1:5300/user/reset_pass?token=' + token
#     html_message = '<p>尊敬的用户您好！</p>' \
#                    '<p>您的邮箱为：%s 。请点击此链接激活您的邮箱(该链接五分钟内有效，请及时验证)：</p>' \
#                    '<p><a href="%s">%s<a></p>' % (email, verify_url, verify_url)
#     sendMail.SendMail('1013697949@qq.com', html_message)
#
#     return jsonify(message='邮箱发送成功，请查收')
#
#
# @BP.route('check_token', methods=['POST', 'GET'])
# def check_token():
#
#     # 获取token值
#     token = request.args.get('token')
#
#     if not token:
#         return jsonify(message='缺少token值')
#
#     try:
#         # 校验token值
#         data = AuthToken().verify_auth_token(token)
#     except Exception as e:
#         logging.error(e)
#         return jsonify(message='token失效')
#
#     # 取出token值作对比
#     sql = """select email from user where reset_password_token=%s"""
#     res, result = db.fetch_one(sql, token)
#
#     if not res:
#         return jsonify(message='获取数据库token失败')
#
#     email = data['email']
#
#     real_email = result[0]
#
#     if email != real_email:
#         return jsonify(message='请求失败')
#
#     return jsonify(message='验证成功')
#
#
# @BP.route('reset_pass', methods=['POST', 'GET'])
# def reset_pass():
#
#     # 获取参数
#     global email
#
#     new_password = request.json.get('new_password')
#     new_password_again = request.json.get('new_password_again')
#
#     if not all([new_password, new_password_again]):
#         return jsonify(message='参数不全')
#
#     if new_password != new_password_again:
#         return jsonify(message='两次输入的密码不匹配')
#
#     new_password = generate_password_hash(new_password)
#
#     sql = """update user set password=%s where email=%s"""
#     db.update(sql, (new_password, email))
#
#     return jsonify(message='修改密码成功')
#
#
# @BP.route('logout', methods=['POST', 'GET'])
# def logout():
#
#     # 删除session信息
#     session.pop('name', None)
#
#     return jsonify(message='注销成功')
