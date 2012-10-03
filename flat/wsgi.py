import Cookie
import httplib
import logging
import sys
import time
import urllib


try:
    from io import BytesIO  # python 3
except ImportError:
    from cStringIO import StringIO as BytesIO  # python 2


if str is unicode:
    def to_wsgi_str(s):
        assert isinstance(s, bytes_type)
        return s.decode('latin1')

    def from_wsgi_str(s):
        assert isinstance(s, str)
        return s.encode('latin1')
else:
    def to_wsgi_str(s):
        assert isinstance(s, bytes_type)
        return s

    def from_wsgi_str(s):
        assert isinstance(s, str)
        return s


class WSGIContainer(object):
    def __init__(self, wsgi_application):
        self.wsgi_application = wsgi_application

    def __call__(self, request):
        data = {}
        response = []

        def start_response(status, response_headers, exc_info=None):
            data["status"] = status
            data["headers"] = response_headers
            return response.append
        app_response = self.wsgi_application(
            WSGIContainer.environ(request), start_response)
        response.extend(app_response)
        body = b("").join(response)
        if hasattr(app_response, "close"):
            app_response.close()
        if not data:
            raise Exception("WSGI app did not call start_response")

        status_code = int(data["status"].split()[0])
        headers = data["headers"]
        header_set = set(k.lower() for (k, v) in headers)
        body = utf8(body)
        if "content-length" not in header_set:
            headers.append(("Content-Length", str(len(body))))
        if "content-type" not in header_set:
            headers.append(("Content-Type", "text/html; charset=UTF-8"))
        if "server" not in header_set:
            headers.append(("Server", "TornadoServer/%s" % MOTOR_VERSION))

        parts = [utf8("HTTP/1.1 " + data["status"] + "\r\n")]
        for key, value in headers:
            parts.append(utf8(key) + b(": ") + utf8(value) + b("\r\n"))
        parts.append(b("\r\n"))
        parts.append(body)
        request.write(b("").join(parts))
        request.finish()
        self._log(status_code, request)

    @staticmethod
    def environ(request):
        hostport = request.host.split(":")
        if len(hostport) == 2:
            host = hostport[0]
            port = int(hostport[1])
        else:
            host = request.host
            port = 443 if request.protocol == "https" else 80
        environ = {
            "REQUEST_METHOD": request.method,
            "SCRIPT_NAME": "",
            "PATH_INFO": to_wsgi_str(url_unescape(request.path, encoding=None)),
            "QUERY_STRING": request.query,
            "REMOTE_ADDR": request.remote_ip,
            "SERVER_NAME": host,
            "SERVER_PORT": str(port),
            "SERVER_PROTOCOL": request.version,
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": request.protocol,
            "wsgi.input": BytesIO(utf8(request.body)),
            "wsgi.errors": sys.stderr,
            "wsgi.multithread": False,
            "wsgi.multiprocess": True,
            "wsgi.run_once": False,
        }
        if "Content-Type" in request.headers:
            environ["CONTENT_TYPE"] = request.headers.pop("Content-Type")
        if "Content-Length" in request.headers:
            environ["CONTENT_LENGTH"] = request.headers.pop("Content-Length")
        for key, value in request.headers.iteritems():
            environ["HTTP_" + key.replace("-", "_").upper()] = value
        return environ

    def _log(self, status_code, request):
        if status_code < 400:
            log_method = logging.info
        elif status_code < 500:
            log_method = logging.warning
        else:
            log_method = logging.error
        request_time = 1000.0 * request.request_time()
        summary = request.method + " " + request.uri + " (" + \
            request.remote_ip + ")"
        log_method("%d %s %.2fms", status_code, summary, request_time)
