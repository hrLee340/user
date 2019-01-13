from lib.redis import redis_store

MYSQL = {
    'user': 'root',
    'password': 'testing_root',
    'port': 3306,
    'host': '172.16.0.11',
    'database':'ucenter',
    'maxconnections': 100
}


PORT = 5300

SECRET_KEY = "EjpNVSNQTyGi1VvWECj9TvC/+kq3oujee2kTfQUs8yCM6xX9Yjq52v54g+HVoknA"

# flask_session的配置信息
SESSION_TYPE = "redis"  # 指定 session 保存到 redis 中
# SESSION_USE_SIGNER = True  # 让 cookie 中的 session_id 被加密签名处理
SESSION_REDIS = redis_store # 使用 redis 的实例
PERMANENT_SESSION_LIFETIME = 86400  # session 的有效期，单位是秒

# if get_env() == 'dev':
#     MYSQL = {}
