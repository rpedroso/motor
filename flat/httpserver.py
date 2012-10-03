

import Cookie
import logging
import socket
import time


try:
    import ssl  # Python 2.6+
except ImportError:
    ssl = None


class HTTPServer(TCPServer):
    def __init__(self, request_callback, no_keep_alive=False, io_loop=None,
                 xheaders=False, ssl_options=None, **kwargs):
        self.request_callback = request_callback
        self.no_keep_alive = no_keep_alive
        self.xheaders = xheaders
        TCPServer.__init__(self, io_loop=io_loop, ssl_options=ssl_options,
                           **kwargs)

    def handle_stream(self, stream, address):
        HTTPConnection(stream, address, self.request_callback,
                       self.no_keep_alive, self.xheaders)


class _BadRequestException(Exception):
    pass


class HTTPConnection(object):
    def __init__(self, stream, address, request_callback, no_keep_alive=False,
                 xheaders=False):
        self.stream = stream
        self.address = address
        self.request_callback = request_callback
        self.no_keep_alive = no_keep_alive
        self.xheaders = xheaders
        self._request = None
        self._request_finished = False
        self._header_callback = wrap(self._on_headers)
        self.stream.read_until(b("\r\n\r\n"), self._header_callback)
        self._write_callback = None

    def close(self):
        self.stream.close()
        self._header_callback = None

    def write(self, chunk, callback=None):
        assert self._request, "Request closed"
        if not self.stream.closed():
            self._write_callback = wrap(callback)
            self.stream.write(chunk, self._on_write_complete)

    def finish(self):
        assert self._request, "Request closed"
        self._request_finished = True
        if not self.stream.writing():
            self._finish_request()

    def _on_write_complete(self):
        if self._write_callback is not None:
            callback = self._write_callback
            self._write_callback = None
            callback()
        if self._request_finished and not self.stream.writing():
            self._finish_request()

    def _finish_request(self):
        if self.no_keep_alive:
            disconnect = True
        else:
            connection_header = self._request.headers.get("Connection")
            if connection_header is not None:
                connection_header = connection_header.lower()
            if self._request.supports_http_1_1():
                disconnect = connection_header == "close"
            elif ("Content-Length" in self._request.headers
                    or self._request.method in ("HEAD", "GET")):
                disconnect = connection_header != "keep-alive"
            else:
                disconnect = True
        self._request = None
        self._request_finished = False
        if disconnect:
            self.close()
            return
        self.stream.read_until(b("\r\n\r\n"), self._header_callback)

    def _on_headers(self, data):
        try:
            data = native_str(data.decode('latin1'))
            eol = data.find("\r\n")
            start_line = data[:eol]
            try:
                method, uri, version = start_line.split(" ")
            except ValueError:
                raise _BadRequestException("Malformed HTTP request line")
            if not version.startswith("HTTP/"):
                raise _BadRequestException("Malformed HTTP version in HTTP Request-Line")
            headers = HTTPHeaders.parse(data[eol:])

            if getattr(self.stream.socket, 'family', socket.AF_INET) in (
                socket.AF_INET, socket.AF_INET6):
                remote_ip = self.address[0]
            else:
                remote_ip = '0.0.0.0'

            self._request = HTTPRequest(
                connection=self, method=method, uri=uri, version=version,
                headers=headers, remote_ip=remote_ip)

            content_length = headers.get("Content-Length")
            if content_length:
                content_length = int(content_length)
                if content_length > self.stream.max_buffer_size:
                    raise _BadRequestException("Content-Length too long")
                if headers.get("Expect") == "100-continue":
                    self.stream.write(b("HTTP/1.1 100 (Continue)\r\n\r\n"))
                self.stream.read_bytes(content_length, self._on_request_body)
                return

            self.request_callback(self._request)
        except _BadRequestException, e:
            logging.info("Malformed HTTP request from %s: %s",
                         self.address[0], e)
            self.close()
            return

    def _on_request_body(self, data):
        self._request.body = data
        if self._request.method in ("POST", "PATCH", "PUT"):
            parse_body_arguments(
                self._request.headers.get("Content-Type", ""), data,
                self._request.arguments, self._request.files)
        self.request_callback(self._request)


class HTTPRequest(object):
    def __init__(self, method, uri, version="HTTP/1.0", headers=None,
                 body=None, remote_ip=None, protocol=None, host=None,
                 files=None, connection=None):
        self.method = method
        self.uri = uri
        self.version = version
        self.headers = headers or HTTPHeaders()
        self.body = body or ""
        if connection and connection.xheaders:
            self.remote_ip = self.headers.get(
                "X-Real-Ip", self.headers.get("X-Forwarded-For", remote_ip))
            if not self._valid_ip(self.remote_ip):
                self.remote_ip = remote_ip
            self.protocol = self.headers.get(
                "X-Scheme", self.headers.get("X-Forwarded-Proto", protocol))
            if self.protocol not in ("http", "https"):
                self.protocol = "http"
        else:
            self.remote_ip = remote_ip
            if protocol:
                self.protocol = protocol
            elif connection and isinstance(connection.stream,
                                           SSLIOStream):
                self.protocol = "https"
            else:
                self.protocol = "http"
        self.host = host or self.headers.get("Host") or "127.0.0.1"
        self.files = files or {}
        self.connection = connection
        self._start_time = time.time()
        self._finish_time = None

        self.path, sep, self.query = uri.partition('?')
        arguments = parse_qs_bytes(self.query)
        self.arguments = {}
        for name, values in arguments.iteritems():
            values = [v for v in values if v]
            if values:
                self.arguments[name] = values

    def supports_http_1_1(self):
        return self.version == "HTTP/1.1"

    @property
    def cookies(self):
        if not hasattr(self, "_cookies"):
            self._cookies = Cookie.SimpleCookie()
            if "Cookie" in self.headers:
                try:
                    self._cookies.load(
                        native_str(self.headers["Cookie"]))
                except Exception:
                    self._cookies = {}
        return self._cookies

    def write(self, chunk, callback=None):
        assert isinstance(chunk, bytes_type)
        self.connection.write(chunk, callback=callback)

    def finish(self):
        self.connection.finish()
        self._finish_time = time.time()

    def full_url(self):
        return self.protocol + "://" + self.host + self.uri

    def request_time(self):
        if self._finish_time is None:
            return time.time() - self._start_time
        else:
            return self._finish_time - self._start_time

    def get_ssl_certificate(self, binary_form=False):
        try:
            return self.connection.stream.socket.getpeercert(
                binary_form=binary_form)
        except ssl.SSLError:
            return None

    def __repr__(self):
        attrs = ("protocol", "host", "method", "uri", "version", "remote_ip",
                 "body")
        args = ", ".join(["%s=%r" % (n, getattr(self, n)) for n in attrs])
        return "%s(%s, headers=%s)" % (
            self.__class__.__name__, args, dict(self.headers))

    def _valid_ip(self, ip):
        try:
            res = socket.getaddrinfo(ip, 0, socket.AF_UNSPEC,
                                     socket.SOCK_STREAM,
                                     0, socket.AI_NUMERICHOST)
            return bool(res)
        except socket.gaierror, e:
            if e.args[0] == socket.EAI_NONAME:
                return False
            raise
        return True
