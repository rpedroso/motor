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
    import sys
    if len(sys.argv) != 2:
        print >>sys.stderr, "%s <web2py_path>" % sys.argv[0]
        sys.exit(1)

    import os
    os.chdir(sys.argv[1])
    sys.path.insert(0, sys.argv[1])
    import gluon
    import gluon.main

    app = motor.WSGIContainer(gluon.main.wsgibase)

    http_server = motor.HTTPServer(app)
    http_server.bind(8888)
    http_server.start(0)
    motor.IOLoop.instance().start()

