# -*- coding: utf-8 -*-

"""
    stash
    ~~~~~

    Implements real-time read proxy traffic information, to re-write and write to the database.
    实现了实时读取代理的流量信息，去重并写入数据库。

    Usage:
        python stash.py proxy.mitm

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/FeeiCN/WebProxy
    :license:   GPL, see LICENSE for more details.
    :copyright: Copyright (c) 2018 Feei. All rights reserved
"""
import os
import sys
import time
import json
import hashlib
import base64
import logging
import colorlog
import traceback
import pymysql.cursors
import pymysql.err

handler = colorlog.StreamHandler()
formatter = colorlog.ColoredFormatter(
    '%(log_color)s%(asctime)s [%(name)s] [%(levelname)s] %(message)s%(reset)s',
    datefmt=None,
    reset=True,
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    },
    secondary_log_colors={},
    style='%'
)
handler.setFormatter(formatter)
logger = colorlog.getLogger('t1.proxy')
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

if 'host' not in os.environ or 'user' not in os.environ or 'password' not in os.environ or 'database' not in os.environ:
    logger.critical('Please set env, host/user/password/database(ex: export host=127.0.0.1)')
    exit(0)

if len(sys.argv) < 2:
    logger.critical('Usage: python stash.py proxy.mitm')
    exit(0)

logger.info('starting, connect database')
con = pymysql.connect(host=os.environ['host'], user=os.environ['user'], password=os.environ['password'], db=os.environ['database'], charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)
sql_exist_table = "SELECT id FROM `flow` WHERE `id`=1"
sql_create_table = """
CREATE TABLE `flow` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `req.method` varchar(8) DEFAULT NULL,
  `req.scheme` varchar(10) DEFAULT NULL,
  `req.host` varchar(512) DEFAULT NULL,
  `req.port` int(11) DEFAULT NULL,
  `req.path` text,
  `req.headers` text,
  `req.content` blob,
  `req.start` double DEFAULT NULL,
  `req.keys` varchar(256) DEFAULT NULL,
  `req.hash` char(64) DEFAULT NULL,
  `resp.code` smallint(6) DEFAULT NULL,
  `resp.reason` varchar(128) DEFAULT NULL,
  `resp.headers` text,
  `resp.content` blob,
  `created` datetime DEFAULT NULL,
  `updated` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=581 DEFAULT CHARSET=utf8mb4;
"""
with con.cursor() as cursor:
    try:
        cursor.execute(sql_exist_table)
        cursor.fetchone()
    except pymysql.err.ProgrammingError:
        logger.info('table not exist, creating...')
        cursor.execute(sql_create_table)
        con.commit()
logger.info('connect success, tail file...')
try:
    def hash_exist(req_hash):
        with con.cursor() as cursor:
            sql = 'SELECT `id`, `req.keys` FROM `flow` WHERE `req.hash`=%s'
            cursor.execute(sql, (req_hash,))
            ret = cursor.fetchone()
            if ret is None:
                return False
            else:
                return ret


    def insert(flow, req_hash, req_keys):
        try:
            with con.cursor() as cursor:
                sql = """INSERT INTO `flow` (
                    `req.method`,
                    `req.scheme`,
                    `req.host`,
                    `req.port`,
                    `req.path`,
                    `req.headers`,
                    `req.content`,
                    `req.start`,
                    `req.keys`,
                    `req.hash`,
                    `resp.code`,
                    `resp.reason`,
                    `resp.headers`,
                    `resp.content`,
                    `created`) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
                req_headers = ''
                resp_headers = ''
                for x in flow['request']['headers']:
                    req_headers += ': '.join(x) + '\n'
                for x in flow['response']['headers']:
                    resp_headers += ': '.join(x) + '\n'
                current_time = time.strftime('%Y-%m-%d %X', time.localtime())
                req_content = base64.b64decode(flow['request']['content'])
                resp_content = base64.b64decode(flow['response']['content'])
                flow_data = (
                    flow['request']['method'],
                    flow['request']['scheme'],
                    flow['request']['host'],
                    flow['request']['port'],
                    flow['request']['path'],
                    req_headers,
                    req_content,
                    flow['request']['timestamp_start'],
                    # ','.join(req_keys),
                    req_keys,
                    req_hash,
                    flow['response']['status_code'],
                    flow['response']['reason'],
                    resp_headers,
                    resp_content,
                    current_time,
                )
                cursor.execute(sql, flow_data)
            con.commit()
        except pymysql.err.DataError as e:
            logger.error('Data exception')
            logger.error(traceback.format_exc())


    def request_hash_and_keys(flow):
        path = flow['request']['path']
        # 处理path本身，拿到paths x.com/x/y/z?a=1
        if '?' in path:
            path_base = path.split('?')[0]
        else:
            path_base = path
        if '/' in path_base:
            # x.com/x/y/z
            paths = ''.join(path_base.split('/'))
        else:
            # x.com
            paths = ''

        # 处理params，找到keys
        # keys = []
        # if '?' in path:
        #     path_split_question = path.split('?')
        #     # 存在query参数，存储query key
        #     # 比如x.com/x/y/z?a=1&b=2，储存a,b
        #     query = path_split_question[1]  # a=1&b=2
        #     if '&' in query:
        #         # [a=1,b=2]
        #         kvs = query.split('&')
        #     else:
        #         # [a=1]
        #         kvs = [query]
        #     for kv in kvs:
        #         if '=' in kv:
        #             # a
        #             keys.append(kv.split('=')[0])
        #         else:
        #             # a
        #             keys.append(kv)

        # 保留 url query 的 keys & values
        keys = ''
        if '?' in path:
            keys = path.split('?')[1:]
            keys = '?'.join(keys)

        # 计算hash
        data = '{method}{scheme}{host}{port}{path}'.format(
            method=flow['request']['method'],
            scheme=flow['request']['scheme'],
            host=flow['request']['host'],
            port=flow['request']['port'],
            path=paths,
        )
        return hashlib.md5(data.encode()).hexdigest(), keys


    with open(sys.argv[1]) as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            line = line.strip().encode()
            if line and line != b'':
                flow = json.loads(line)
                # logger.info(flow)
                # 静态资源有可能是由动态程序输出的，得考虑如何区分出再做过滤

                # 计算一次请求唯一ID
                req_hash, req_keys = request_hash_and_keys(flow)
                # 根据唯一ID判断是否存在
                exist_hash = hash_exist(req_hash)
                if exist_hash:
                    # 存在则比较keys数量，新数量小于老的数量则不做处理，新数量大于老的数量则更新keys/path
                    logger.info('{0} {1} {2} {3}'.format(flow['request']['host'], req_hash, req_keys, 'exist', exist_hash))
                else:
                    # 不存在则写入
                    insert(flow, req_hash, req_keys)
                    logger.info('{0} {1} {2} {3}'.format(flow['request']['host'], req_hash, req_keys, 'success'))
                time.sleep(0.1)
finally:
    con.close()
