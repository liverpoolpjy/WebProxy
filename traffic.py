# -*- coding: utf-8 -*-

"""
    traffic
    ~~~~~~~

    Implements the proxy server request traffic in real-time into the file.
    实现将代理服务器中的请求流量实时写入文件。

    Usage:
        mitmdump -p 8088 -s traffic.py

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/FeeiCN/WebProxy
    :license:   GPL, see LICENSE for more details.
    :copyright: Copyright (c) 2018 Feei. All rights reserved
"""
import sys
import json
import traceback
import base64
from mitmproxy import http, ctx, websocket

if len(sys.argv) < 2:
    print('Usage: mitmdump -p 8088 -s traffic.py')
    exit(0)


class DateEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode()
        return json.JSONEncoder.default(self, obj)


# Response Event
# 在响应事件中做可以同时取到Request和Response
# http://docs.mitmproxy.org/en/latest/scripting/events.html#response
def response(flow: http.HTTPFlow) -> None:
    with open('proxy.mitm', 'a') as f:
        try:
            data = flow.get_state()
            # 去掉不需要的信息
            data.pop('client_conn', None)
            data.pop('server_conn', None)
            # 为提高传输效率，HTTP协议会存在gzip压缩传输内容的情况
            # 由于HTTP协议特性，浏览器端无法在访问网页时知道服务端是否支持gzip压缩
            # 所以大部分业务场景下都是响应（Response）内容使用gzip压缩，而请求（Request）内容是明文。
            # 而对于结果gzip压缩的响应内容，在MITMProxy中可以通过`-z`选项打开即可解压缩响应内容
            # 在部分业务场景下，请求的内容也非常多，所以为提升传输效率也会对请求内容进行gzip压缩
            # 对于这类场景，MITMProxy目前是无法支持的，已提交ISSUE（https://github.com/mitmproxy/mitmproxy/issues/2782）
            data['request']['content'] = base64.b64encode(data['request']['content'])
            data['response']['content'] = base64.b64encode(data['response']['content'])
            # 转为JSON
            data = json.dumps(data, cls=DateEncoder)
            # 写文件以换行来区分每个请求
            f.write(data + '\n')
        except UnicodeDecodeError as e:
            ctx.log.error(data)
            traceback.print_exc()
            ctx.log.error('Decode failed')


def websocket_end(flow: websocket.flow) -> None:
    ctx.log.info(flow)


# Done Event
# http://docs.mitmproxy.org/en/latest/scripting/events.html#done
def done():
    ctx.log.info('Done')
