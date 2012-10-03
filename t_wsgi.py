import motor

def simple_app(environ, start_response):
    status = '200 OK'
    message = "You requested %s\n" % environ['PATH_INFO']

    headers = [("Connection", "keep-alive"),
    ]

    start_response(status, headers)

    ret = (message,)
    return ret

if __name__ == '__main__':
    app = motor.WSGIContainer(simple_app)
    http_server = motor.HTTPServer(app)
    http_server.bind(8888)
    http_server.start(2)
    motor.IOLoop.instance().start()

