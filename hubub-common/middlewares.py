# -*- coding: utf-8 -*-
import logging
import os
import time
import pprint

from sanic.response import text, json

__all__ = (
    'setup_middleware'
)


def setup_middleware(app):

    @app.middleware
    async def before_request(request):

        logging.getLogger().info('********* ********* API Call Details ********* *********')
        logging.getLogger().info('Requested: ' + request.url)
        logging.getLogger().info('Server Name: ' + request.host)
        logging.getLogger().info('Request Method: ' + request.method)
        logging.getLogger().info("Server Process Id:" + str(os.getpid()))
        logging.getLogger().info('********* User Details *********')
        logging.getLogger().info('User IP Address: ' + request.remote_addr)
        logging.getLogger().info('User IP Address: ' + request.ip[0])
        logging.getLogger().info('User Port: ' + str(request.ip[1]))
        if 'user-agent' in request.headers:
            logging.getLogger().info('User Agent: ' + str(request.headers['user-agent']))
        if hasattr(request.headers, 'params'):
            logging.getLogger().info('Parameters: ' + json(request.params))
        if hasattr(request.headers, 'args'):
            logging.getLogger().info('Parameters: ' + json(request.args))
        logging.getLogger().info('********* ********* ********* ********* *********')
        logging.getLogger().info('timestamp:'+ str(int(time.time())))

        if request.method == "OPTIONS":
            return text("ok")

    @app.route('/')
    async def default(request):
        defx = json({"test": True})
        return defx

    @app.middleware('response')
    async def cors(request, response):

        origin=''
        if hasattr(request, 'headers'):
            request.headers.get('origin')
            if 'origin' in request.headers:

                logging.getLogger().info('Request Origin:' + request.headers['origin'])
                origin = request.headers['origin']
            else:
                logging.getLogger().info('Request Origin:' + app.hububconfig.get("FRONTEND_DEFAULT_URL"))
                origin = app.hububconfig.get("FRONTEND_DEFAULT_URL")

        logging.getLogger().info('Origin:' + origin)


        if hasattr(response, 'headers'):
            response.headers["Access-Control-Allow-Methods"] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers["Access-Control-Allow-Headers"] = 'Content-Type,Authentication,X-hubub-Authentication-Version,X-hubub-Authentication-Timestamp,Content-Type,Access-Control-Expose-Headers,Access-Control-Allow-Credentials,Access-Control-Allow-Origin'
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = 'true'
            response.headers["Access-Control-Expose-Headers"] = 'Set-Cookie'
            response.headers["Access-Control-Max-Age"] = 3600
            response.headers["Content-Type"] = 'application/json charset=UTF-8'

        if request.method == "OPTIONS":
            response.headers["Content-Length"] = 0
        return


class flask_middleware(object):

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # pp = pprint.PrettyPrinter(depth=6)
        # pp.pprint(environ)
        return self.app(environ, start_response)