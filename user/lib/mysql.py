import pymysql

from DBUtils.PooledDB import PooledDB
from config import MYSQL


class MySql:
    def __init__(self):
        self.__POOL = PooledDB(creator=pymysql, **MYSQL)

    def get_connection(self):
        return self.__POOL.connection()

    def __write(self, sql, params):
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(sql, params)
            conn.commit()
        except Exception as err:
            conn.rollback()
            raise err
        finally:
            cursor.close()
            conn.close()

    def __read_one(self, sql, params):
        conn = self.get_connection()
        cursor = conn.cursor()
        res = cursor.execute(sql, params)
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return res, result

    def __read__all(self, sql, params):
        conn = self.get_connection()
        cursor = conn.cursor()
        res = cursor.execute(sql, params)
        result = cursor.fetchall()
        cursor.close()
        conn.close()
        return result

    def fetch_one(self, sql, params):
        res, result = self.__read_one(sql, params)
        return res if res else None, result

    def fetch_all(self, sql, params):
        return self.__read__all(sql, params)

    def insert(self, sql, params):
        self.__write(sql, params)

    def update(self, sql, params):
        self.__write(sql, params)

    def delete(self, sql, params):
        self.__write(sql, params)
