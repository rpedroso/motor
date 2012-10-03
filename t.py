from motor import HTTPServer, IOLoop

def handle_request(request):
   message = "You requested %s\n" % request.uri
   request.write("HTTP/1.1 200 OK"
                    "\r\nContent-Length: %d"
                    "\r\nConnection: keep-alive\r\n"
                    "\r\n%s" % (
                 len(message), message))
   request.finish()

if __name__ == '__main__':
    http_server = HTTPServer(handle_request)
    http_server.bind(8888)
    http_server.start(0)
    IOLoop.instance().start()

