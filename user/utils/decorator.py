import time, logging
from functools import wraps
from utils.captcha.captcha import captcha
from utils import constants
from lib.redis import redis_store
from flask import request, make_response, abort


def stat_called_time(func):

    # 装饰器内的变量继承每次调用后的变化，变量就必须设置为可变类型
    limit_times = [3]
    cache = {}

    @wraps(func)
    def _called_time(*args, **kwargs):
        key = func.__name__
        if key in cache.keys():
            [call_times, updatetime] = cache[key]
            if time.time() - updatetime < 60:
                cache[key][0] += 1
            else:
                cache[key] = [1, time.time()]
        else:
            call_times = 1
            cache[key] = [call_times, time.time()]

        if cache[key][0] <= limit_times[0]:
            res = func(*args, **kwargs)
            cache[key][1] = time.time()
            return res
        else:
            print("超过调用次数了")

            # 生成验证码
            text, image = captcha.generate_captcha()
            ip = request.remote_addr

            # 3. 保存到redis中
            try:
                # redis_store = None  # type: redis.StrictRedis
                redis_store.setex('ip_' + ip, constants.IMAGE_CODE_REDIS_EXPIRES, text)
            except Exception as e:
                # 3.1 日志记录错误
                logging.error(e)
                return abort(403)

            response = make_response(image)
            response.headers['Content-Type'] = 'image/jpg'
            return response

    return _called_time
