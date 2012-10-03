#!/usr/bin/env python
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# This file is an experimental monolithic build of tornado HTTPServer

from __future__ import absolute_import, division, with_statement
MOTOR_VERSION = '2.4.0.0'
import errno
import logging
import os
import socket
import stat


try:
    import ssl  # Python 2.6+
except ImportError:
    ssl = None


class TCPServer(object):
    def __init__(self, io_loop=None, ssl_options=None):
        self.io_loop = io_loop
        self.ssl_options = ssl_options
        self._sockets = {}  # fd -> socket object
        self._pending_sockets = []
        self._started = False

        if self.ssl_options is not None:
            if 'certfile' not in self.ssl_options:
                raise KeyError('missing key "certfile" in ssl_options')

            if not os.path.exists(self.ssl_options['certfile']):
                raise ValueError('certfile "%s" does not exist' %
                    self.ssl_options['certfile'])
            if ('keyfile' in self.ssl_options and
                    not os.path.exists(self.ssl_options['keyfile'])):
                raise ValueError('keyfile "%s" does not exist' %
                    self.ssl_options['keyfile'])

    def listen(self, port, address=""):
        sockets = bind_sockets(port, address=address)
        self.add_sockets(sockets)

    def add_sockets(self, sockets):
        if self.io_loop is None:
            self.io_loop = IOLoop.instance()

        for sock in sockets:
            self._sockets[sock.fileno()] = sock
            add_accept_handler(sock, self._handle_connection,
                               io_loop=self.io_loop)

    def add_socket(self, socket):
        self.add_sockets([socket])

    def bind(self, port, address=None, family=socket.AF_UNSPEC, backlog=128):
        sockets = bind_sockets(port, address=address, family=family,
                               backlog=backlog)
        if self._started:
            self.add_sockets(sockets)
        else:
            self._pending_sockets.extend(sockets)

    def start(self, num_processes=1):
        assert not self._started
        self._started = True
        if num_processes != 1:
            fork_processes(num_processes)
        sockets = self._pending_sockets
        self._pending_sockets = []
        self.add_sockets(sockets)

    def stop(self):
        for fd, sock in self._sockets.iteritems():
            self.io_loop.remove_handler(fd)
            sock.close()

    def handle_stream(self, stream, address):
        raise NotImplementedError()

    def _handle_connection(self, connection, address):
        if self.ssl_options is not None:
            assert ssl, "Python 2.6+ and OpenSSL required for SSL"
            try:
                connection = ssl.wrap_socket(connection,
                                             server_side=True,
                                             do_handshake_on_connect=False,
                                             **self.ssl_options)
            except ssl.SSLError, err:
                if err.args[0] == ssl.SSL_ERROR_EOF:
                    return connection.close()
                else:
                    raise
            except socket.error, err:
                if err.args[0] == errno.ECONNABORTED:
                    return connection.close()
                else:
                    raise
        try:
            if self.ssl_options is not None:
                stream = SSLIOStream(connection, io_loop=self.io_loop)
            else:
                stream = IOStream(connection, io_loop=self.io_loop)
            self.handle_stream(stream, address)
        except Exception:
            logging.error("Error in connection callback", exc_info=True)


def bind_sockets(port, address=None, family=socket.AF_UNSPEC, backlog=128):
    sockets = []
    if address == "":
        address = None
    flags = socket.AI_PASSIVE
    if hasattr(socket, "AI_ADDRCONFIG"):
        flags |= socket.AI_ADDRCONFIG
    for res in set(socket.getaddrinfo(address, port, family, socket.SOCK_STREAM,
                                  0, flags)):
        af, socktype, proto, canonname, sockaddr = res
        sock = socket.socket(af, socktype, proto)
        set_close_exec(sock.fileno())
        if os.name != 'nt':
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if af == socket.AF_INET6:
            if hasattr(socket, "IPPROTO_IPV6"):
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.setblocking(0)
        sock.bind(sockaddr)
        sock.listen(backlog)
        sockets.append(sock)
    return sockets

if hasattr(socket, 'AF_UNIX'):
    def bind_unix_socket(file, mode=0600, backlog=128):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        set_close_exec(sock.fileno())
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(0)
        try:
            st = os.stat(file)
        except OSError, err:
            if err.errno != errno.ENOENT:
                raise
        else:
            if stat.S_ISSOCK(st.st_mode):
                os.remove(file)
            else:
                raise ValueError("File %s exists and is not a socket", file)
        sock.bind(file)
        os.chmod(file, mode)
        sock.listen(backlog)
        return sock


def add_accept_handler(sock, callback, io_loop=None):
    if io_loop is None:
        io_loop = IOLoop.instance()

    def accept_handler(fd, events):
        while True:
            try:
                connection, address = sock.accept()
            except socket.error, e:
                if e.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    return
                raise
            callback(connection, address)
    io_loop.add_handler(sock.fileno(), accept_handler, IOLoop.READ)


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
import os
if os.name == 'nt':
    import ctypes
    import ctypes.wintypes

    SetHandleInformation = ctypes.windll.kernel32.SetHandleInformation
    SetHandleInformation.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD)
    SetHandleInformation.restype = ctypes.wintypes.BOOL

    HANDLE_FLAG_INHERIT = 0x00000001


    def set_close_exec(fd):
        success = SetHandleInformation(fd, HANDLE_FLAG_INHERIT, 0)
        if not success:
            raise ctypes.GetLastError()

    import errno
    import socket

    class Waker(object):
        def __init__(self):

            self.writer = socket.socket()
            self.writer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            count = 0
            while 1:
                count += 1
                a = socket.socket()
                a.bind(("127.0.0.1", 0))
                a.listen(1)
                connect_address = a.getsockname()  # assigned (host, port) pair
                try:
                    self.writer.connect(connect_address)
                    break    # success
                except socket.error, detail:
                    if (not hasattr(errno, 'WSAEADDRINUSE') or
                        detail[0] != errno.WSAEADDRINUSE):
                        raise
                    if count >= 10:  # I've never seen it go above 2
                        a.close()
                        self.writer.close()
                        raise socket.error("Cannot bind trigger!")
                    a.close()

            self.reader, addr = a.accept()
            self.reader.setblocking(0)
            self.writer.setblocking(0)
            a.close()
            self.reader_fd = self.reader.fileno()

        def fileno(self):
            return self.reader.fileno()

        def wake(self):
            try:
                self.writer.send(b("x"))
            except (IOError, socket.error):
                pass

        def consume(self):
            try:
                while True:
                    result = self.reader.recv(1024)
                    if not result:
                        break
            except (IOError, socket.error):
                pass

        def close(self):
            self.reader.close()
            self.writer.close()
else:
    import fcntl
    import os

    def set_close_exec(fd):
        flags = fcntl.fcntl(fd, fcntl.F_GETFD)
        fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)


    def _set_nonblocking(fd):
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


    class Waker(object):
        def __init__(self):
            r, w = os.pipe()
            _set_nonblocking(r)
            _set_nonblocking(w)
            set_close_exec(r)
            set_close_exec(w)
            self.reader = os.fdopen(r, "rb", 0)
            self.writer = os.fdopen(w, "wb", 0)

        def fileno(self):
            return self.reader.fileno()

        def wake(self):
            try:
                self.writer.write(b("x"))
            except IOError:
                pass

        def consume(self):
            try:
                while True:
                    result = self.reader.read()
                    if not result:
                        break
            except IOError:
                pass

        def close(self):
            self.reader.close()
            self.writer.close()


import errno
import logging
import os
import sys
import time

from binascii import hexlify


try:
    import multiprocessing  # Python 2.6+
except ImportError:
    multiprocessing = None


def cpu_count():
    if multiprocessing is not None:
        try:
            return multiprocessing.cpu_count()
        except NotImplementedError:
            pass
    try:
        return os.sysconf("SC_NPROCESSORS_CONF")
    except ValueError:
        pass
    logging.error("Could not detect number of processors; assuming 1")
    return 1


def _reseed_random():
    if 'random' not in sys.modules:
        return
    import random
    try:
        seed = long(hexlify(os.urandom(16)), 16)
    except NotImplementedError:
        seed = int(time.time() * 1000) ^ os.getpid()
    random.seed(seed)


_task_id = None


def fork_processes(num_processes, max_restarts=100):
    global _task_id
    assert _task_id is None
    if num_processes is None or num_processes <= 0:
        num_processes = cpu_count()
    if IOLoop.initialized():
        raise RuntimeError("Cannot run in multiple processes: IOLoop instance "
                           "has already been initialized. You cannot call "
                           "IOLoop.instance() before calling start_processes()")
    logging.info("Starting %d processes", num_processes)
    children = {}

    def start_child(i):
        pid = os.fork()
        if pid == 0:
            _reseed_random()
            global _task_id
            _task_id = i
            return i
        else:
            children[pid] = i
            return None
    for i in range(num_processes):
        id = start_child(i)
        if id is not None:
            return id
    num_restarts = 0
    while children:
        try:
            pid, status = os.wait()
        except OSError, e:
            if e.errno == errno.EINTR:
                continue
            raise
        if pid not in children:
            continue
        id = children.pop(pid)
        if os.WIFSIGNALED(status):
            logging.warning("child %d (pid %d) killed by signal %d, restarting",
                            id, pid, os.WTERMSIG(status))
        elif os.WEXITSTATUS(status) != 0:
            logging.warning("child %d (pid %d) exited with status %d, restarting",
                            id, pid, os.WEXITSTATUS(status))
        else:
            logging.info("child %d (pid %d) exited normally", id, pid)
            continue
        num_restarts += 1
        if num_restarts > max_restarts:
            raise RuntimeError("Too many child restarts, giving up")
        new_id = start_child(id)
        if new_id is not None:
            return new_id
    sys.exit(0)


def task_id():
    global _task_id
    return _task_id


import datetime
import errno
import heapq
import os
import logging
import select
import thread
import threading
import time
import traceback


try:
    import signal
except ImportError:
    signal = None



class IOLoop(object):
    _EPOLLIN = 0x001
    _EPOLLPRI = 0x002
    _EPOLLOUT = 0x004
    _EPOLLERR = 0x008
    _EPOLLHUP = 0x010
    _EPOLLRDHUP = 0x2000
    _EPOLLONESHOT = (1 << 30)
    _EPOLLET = (1 << 31)

    NONE = 0
    READ = _EPOLLIN
    WRITE = _EPOLLOUT
    ERROR = _EPOLLERR | _EPOLLHUP

    _instance_lock = threading.Lock()

    def __init__(self, impl=None):
        self._impl = impl or _poll()
        if hasattr(self._impl, 'fileno'):
            set_close_exec(self._impl.fileno())
        self._handlers = {}
        self._events = {}
        self._callbacks = []
        self._callback_lock = threading.Lock()
        self._timeouts = []
        self._running = False
        self._stopped = False
        self._thread_ident = None
        self._blocking_signal_threshold = None

        self._waker = Waker()
        self.add_handler(self._waker.fileno(),
                         lambda fd, events: self._waker.consume(),
                         self.READ)

    @staticmethod
    def instance():
        if not hasattr(IOLoop, "_instance"):
            with IOLoop._instance_lock:
                if not hasattr(IOLoop, "_instance"):
                    IOLoop._instance = IOLoop()
        return IOLoop._instance

    @staticmethod
    def initialized():
        return hasattr(IOLoop, "_instance")

    def install(self):
        assert not IOLoop.initialized()
        IOLoop._instance = self

    def close(self, all_fds=False):
        self.remove_handler(self._waker.fileno())
        if all_fds:
            for fd in self._handlers.keys()[:]:
                try:
                    os.close(fd)
                except Exception:
                    logging.debug("error closing fd %s", fd, exc_info=True)
        self._waker.close()
        self._impl.close()

    def add_handler(self, fd, handler, events):
        self._handlers[fd] = wrap(handler)
        self._impl.register(fd, events | self.ERROR)

    def update_handler(self, fd, events):
        self._impl.modify(fd, events | self.ERROR)

    def remove_handler(self, fd):
        self._handlers.pop(fd, None)
        self._events.pop(fd, None)
        try:
            self._impl.unregister(fd)
        except (OSError, IOError):
            logging.debug("Error deleting fd from IOLoop", exc_info=True)

    def set_blocking_signal_threshold(self, seconds, action):
        if not hasattr(signal, "setitimer"):
            logging.error("set_blocking_signal_threshold requires a signal module "
                       "with the setitimer method")
            return
        self._blocking_signal_threshold = seconds
        if seconds is not None:
            signal.signal(signal.SIGALRM,
                          action if action is not None else signal.SIG_DFL)

    def set_blocking_log_threshold(self, seconds):
        self.set_blocking_signal_threshold(seconds, self.log_stack)

    def log_stack(self, signal, frame):
        logging.warning('IOLoop blocked for %f seconds in\n%s',
                        self._blocking_signal_threshold,
                        ''.join(traceback.format_stack(frame)))

    def start(self):
        if self._stopped:
            self._stopped = False
            return
        self._thread_ident = thread.get_ident()
        self._running = True
        while True:
            poll_timeout = 3600.0

            with self._callback_lock:
                callbacks = self._callbacks
                self._callbacks = []
            for callback in callbacks:
                self._run_callback(callback)

            if self._timeouts:
                now = time.time()
                while self._timeouts:
                    if self._timeouts[0].callback is None:
                        heapq.heappop(self._timeouts)
                    elif self._timeouts[0].deadline <= now:
                        timeout = heapq.heappop(self._timeouts)
                        self._run_callback(timeout.callback)
                    else:
                        seconds = self._timeouts[0].deadline - now
                        poll_timeout = min(seconds, poll_timeout)
                        break

            if self._callbacks:
                poll_timeout = 0.0

            if not self._running:
                break

            if self._blocking_signal_threshold is not None:
                signal.setitimer(signal.ITIMER_REAL, 0, 0)

            try:
                event_pairs = self._impl.poll(poll_timeout)
            except Exception, e:
                if (getattr(e, 'errno', None) == errno.EINTR or
                    (isinstance(getattr(e, 'args', None), tuple) and
                     len(e.args) == 2 and e.args[0] == errno.EINTR)):
                    continue
                else:
                    raise

            if self._blocking_signal_threshold is not None:
                signal.setitimer(signal.ITIMER_REAL,
                                 self._blocking_signal_threshold, 0)

            self._events.update(event_pairs)
            while self._events:
                fd, events = self._events.popitem()
                try:
                    self._handlers[fd](fd, events)
                except (OSError, IOError), e:
                    if e.args[0] == errno.EPIPE:
                        pass
                    else:
                        logging.error("Exception in I/O handler for fd %s",
                                      fd, exc_info=True)
                except Exception:
                    logging.error("Exception in I/O handler for fd %s",
                                  fd, exc_info=True)
        self._stopped = False
        if self._blocking_signal_threshold is not None:
            signal.setitimer(signal.ITIMER_REAL, 0, 0)

    def stop(self):
        self._running = False
        self._stopped = True
        self._waker.wake()

    def running(self):
        return self._running

    def add_timeout(self, deadline, callback):
        timeout = _Timeout(deadline, wrap(callback))
        heapq.heappush(self._timeouts, timeout)
        return timeout

    def remove_timeout(self, timeout):
        timeout.callback = None

    def add_callback(self, callback):
        with self._callback_lock:
            list_empty = not self._callbacks
            self._callbacks.append(wrap(callback))
        if list_empty and thread.get_ident() != self._thread_ident:
            self._waker.wake()

    def _run_callback(self, callback):
        try:
            callback()
        except Exception:
            self.handle_callback_exception(callback)

    def handle_callback_exception(self, callback):
        logging.error("Exception in callback %r", callback, exc_info=True)


class _Timeout(object):

    __slots__ = ['deadline', 'callback']

    def __init__(self, deadline, callback):
        if isinstance(deadline, (int, long, float)):
            self.deadline = deadline
        elif isinstance(deadline, datetime.timedelta):
            self.deadline = time.time() + _Timeout.timedelta_to_seconds(deadline)
        else:
            raise TypeError("Unsupported deadline %r" % deadline)
        self.callback = callback

    @staticmethod
    def timedelta_to_seconds(td):
        return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) / float(10 ** 6)

    def __lt__(self, other):
        return ((self.deadline, id(self)) <
                (other.deadline, id(other)))

    def __le__(self, other):
        return ((self.deadline, id(self)) <=
                (other.deadline, id(other)))


class PeriodicCallback(object):
    def __init__(self, callback, callback_time, io_loop=None):
        self.callback = callback
        self.callback_time = callback_time
        self.io_loop = io_loop or IOLoop.instance()
        self._running = False
        self._timeout = None

    def start(self):
        self._running = True
        self._next_timeout = time.time()
        self._schedule_next()

    def stop(self):
        self._running = False
        if self._timeout is not None:
            self.io_loop.remove_timeout(self._timeout)
            self._timeout = None

    def _run(self):
        if not self._running:
            return
        try:
            self.callback()
        except Exception:
            logging.error("Error in periodic callback", exc_info=True)
        self._schedule_next()

    def _schedule_next(self):
        if self._running:
            current_time = time.time()
            while self._next_timeout <= current_time:
                self._next_timeout += self.callback_time / 1000.0
            self._timeout = self.io_loop.add_timeout(self._next_timeout, self._run)


class _EPoll(object):
    _EPOLL_CTL_ADD = 1
    _EPOLL_CTL_DEL = 2
    _EPOLL_CTL_MOD = 3

    def __init__(self):
        self._epoll_fd = epoll.epoll_create()

    def fileno(self):
        return self._epoll_fd

    def close(self):
        os.close(self._epoll_fd)

    def register(self, fd, events):
        epoll.epoll_ctl(self._epoll_fd, self._EPOLL_CTL_ADD, fd, events)

    def modify(self, fd, events):
        epoll.epoll_ctl(self._epoll_fd, self._EPOLL_CTL_MOD, fd, events)

    def unregister(self, fd):
        epoll.epoll_ctl(self._epoll_fd, self._EPOLL_CTL_DEL, fd, 0)

    def poll(self, timeout):
        return epoll.epoll_wait(self._epoll_fd, int(timeout * 1000))


class _KQueue(object):
    def __init__(self):
        self._kqueue = select.kqueue()
        self._active = {}

    def fileno(self):
        return self._kqueue.fileno()

    def close(self):
        self._kqueue.close()

    def register(self, fd, events):
        if fd in self._active:
            raise IOError("fd %d already registered" % fd)
        self._control(fd, events, select.KQ_EV_ADD)
        self._active[fd] = events

    def modify(self, fd, events):
        self.unregister(fd)
        self.register(fd, events)

    def unregister(self, fd):
        events = self._active.pop(fd)
        self._control(fd, events, select.KQ_EV_DELETE)

    def _control(self, fd, events, flags):
        kevents = []
        if events & IOLoop.WRITE:
            kevents.append(select.kevent(
                    fd, filter=select.KQ_FILTER_WRITE, flags=flags))
        if events & IOLoop.READ or not kevents:
            kevents.append(select.kevent(
                    fd, filter=select.KQ_FILTER_READ, flags=flags))
        for kevent in kevents:
            self._kqueue.control([kevent], 0)

    def poll(self, timeout):
        kevents = self._kqueue.control(None, 1000, timeout)
        events = {}
        for kevent in kevents:
            fd = kevent.ident
            if kevent.filter == select.KQ_FILTER_READ:
                events[fd] = events.get(fd, 0) | IOLoop.READ
            if kevent.filter == select.KQ_FILTER_WRITE:
                if kevent.flags & select.KQ_EV_EOF:
                    events[fd] = IOLoop.ERROR
                else:
                    events[fd] = events.get(fd, 0) | IOLoop.WRITE
            if kevent.flags & select.KQ_EV_ERROR:
                events[fd] = events.get(fd, 0) | IOLoop.ERROR
        return events.items()


class _Select(object):
    def __init__(self):
        self.read_fds = set()
        self.write_fds = set()
        self.error_fds = set()
        self.fd_sets = (self.read_fds, self.write_fds, self.error_fds)

    def close(self):
        pass

    def register(self, fd, events):
        if fd in self.read_fds or fd in self.write_fds or fd in self.error_fds:
            raise IOError("fd %d already registered" % fd)
        if events & IOLoop.READ:
            self.read_fds.add(fd)
        if events & IOLoop.WRITE:
            self.write_fds.add(fd)
        if events & IOLoop.ERROR:
            self.error_fds.add(fd)
            self.read_fds.add(fd)

    def modify(self, fd, events):
        self.unregister(fd)
        self.register(fd, events)

    def unregister(self, fd):
        self.read_fds.discard(fd)
        self.write_fds.discard(fd)
        self.error_fds.discard(fd)

    def poll(self, timeout):
        readable, writeable, errors = select.select(
            self.read_fds, self.write_fds, self.error_fds, timeout)
        events = {}
        for fd in readable:
            events[fd] = events.get(fd, 0) | IOLoop.READ
        for fd in writeable:
            events[fd] = events.get(fd, 0) | IOLoop.WRITE
        for fd in errors:
            events[fd] = events.get(fd, 0) | IOLoop.ERROR
        return events.items()


if hasattr(select, "epoll"):
    _poll = select.epoll
elif hasattr(select, "kqueue"):
    _poll = _KQueue
else:
    try:
        from tornado import epoll
        _poll = _EPoll
    except Exception:
        import sys
        if "linux" in sys.platform:
            logging.warning("epoll module not found; using select()")
        _poll = _Select

import contextlib
import functools
import itertools
import operator
import sys
import threading



class _State(threading.local):
    def __init__(self):
        self.contexts = ()
_state = _State()


class StackContext(object):
    def __init__(self, context_factory, _active_cell=None):
        self.context_factory = context_factory
        self.active_cell = _active_cell or [True]

    def __enter__(self):
        self.old_contexts = _state.contexts
        _state.contexts = (self.old_contexts +
                           ((StackContext, self.context_factory, self.active_cell),))
        try:
            self.context = self.context_factory()
            self.context.__enter__()
        except Exception:
            _state.contexts = self.old_contexts
            raise
        return lambda: operator.setitem(self.active_cell, 0, False)

    def __exit__(self, type, value, traceback):
        try:
            return self.context.__exit__(type, value, traceback)
        finally:
            _state.contexts = self.old_contexts


class ExceptionStackContext(object):
    def __init__(self, exception_handler, _active_cell=None):
        self.exception_handler = exception_handler
        self.active_cell = _active_cell or [True]

    def __enter__(self):
        self.old_contexts = _state.contexts
        _state.contexts = (self.old_contexts +
                           ((ExceptionStackContext, self.exception_handler,
                             self.active_cell),))
        return lambda: operator.setitem(self.active_cell, 0, False)

    def __exit__(self, type, value, traceback):
        try:
            if type is not None:
                return self.exception_handler(type, value, traceback)
        finally:
            _state.contexts = self.old_contexts


class NullContext(object):
    def __enter__(self):
        self.old_contexts = _state.contexts
        _state.contexts = ()

    def __exit__(self, type, value, traceback):
        _state.contexts = self.old_contexts


class _StackContextWrapper(functools.partial):
    pass


def wrap(fn):
    if fn is None or fn.__class__ is _StackContextWrapper:
        return fn

    def wrapped(*args, **kwargs):
        callback, contexts, args = args[0], args[1], args[2:]

        if contexts is _state.contexts or not contexts:
            callback(*args, **kwargs)
            return
        if not _state.contexts:
            new_contexts = [cls(arg, active_cell)
                            for (cls, arg, active_cell) in contexts
                            if active_cell[0]]
        elif (len(_state.contexts) > len(contexts) or
            any(a[1] is not b[1]
                for a, b in itertools.izip(_state.contexts, contexts))):
            new_contexts = ([NullContext()] +
                            [cls(arg, active_cell)
                             for (cls, arg, active_cell) in contexts
                             if active_cell[0]])
        else:
            new_contexts = [cls(arg, active_cell)
                            for (cls, arg, active_cell) in contexts[len(_state.contexts):]
                            if active_cell[0]]
        if len(new_contexts) > 1:
            with _nested(*new_contexts):
                callback(*args, **kwargs)
        elif new_contexts:
            with new_contexts[0]:
                callback(*args, **kwargs)
        else:
            callback(*args, **kwargs)
    if _state.contexts:
        return _StackContextWrapper(wrapped, fn, _state.contexts)
    else:
        return _StackContextWrapper(fn)


@contextlib.contextmanager
def _nested(*managers):
    exits = []
    vars = []
    exc = (None, None, None)
    try:
        for mgr in managers:
            exit = mgr.__exit__
            enter = mgr.__enter__
            vars.append(enter())
            exits.append(exit)
        yield vars
    except:
        exc = sys.exc_info()
    finally:
        while exits:
            exit = exits.pop()
            try:
                if exit(*exc):
                    exc = (None, None, None)
            except:
                exc = sys.exc_info()
        if exc != (None, None, None):
            raise_exc_info(exc)

import collections
import errno
import logging
import os
import socket
import sys
import re


try:
    import ssl  # Python 2.6+
except ImportError:
    ssl = None


class IOStream(object):
    def __init__(self, socket, io_loop=None, max_buffer_size=104857600,
                 read_chunk_size=4096):
        self.socket = socket
        self.socket.setblocking(False)
        self.io_loop = io_loop or IOLoop.instance()
        self.max_buffer_size = max_buffer_size
        self.read_chunk_size = read_chunk_size
        self.error = None
        self._read_buffer = collections.deque()
        self._write_buffer = collections.deque()
        self._read_buffer_size = 0
        self._write_buffer_frozen = False
        self._read_delimiter = None
        self._read_regex = None
        self._read_bytes = None
        self._read_until_close = False
        self._read_callback = None
        self._streaming_callback = None
        self._write_callback = None
        self._close_callback = None
        self._connect_callback = None
        self._connecting = False
        self._state = None
        self._pending_callbacks = 0

    def connect(self, address, callback=None):
        self._connecting = True
        try:
            self.socket.connect(address)
        except socket.error, e:
            if e.args[0] not in (errno.EINPROGRESS, errno.EWOULDBLOCK):
                logging.warning("Connect error on fd %d: %s",
                                self.socket.fileno(), e)
                self.close()
                return
        self._connect_callback = wrap(callback)
        self._add_io_state(self.io_loop.WRITE)

    def read_until_regex(self, regex, callback):
        self._set_read_callback(callback)
        self._read_regex = re.compile(regex)
        self._try_inline_read()

    def read_until(self, delimiter, callback):
        self._set_read_callback(callback)
        self._read_delimiter = delimiter
        self._try_inline_read()

    def read_bytes(self, num_bytes, callback, streaming_callback=None):
        self._set_read_callback(callback)
        assert isinstance(num_bytes, (int, long))
        self._read_bytes = num_bytes
        self._streaming_callback = wrap(streaming_callback)
        self._try_inline_read()

    def read_until_close(self, callback, streaming_callback=None):
        self._set_read_callback(callback)
        if self.closed():
            self._run_callback(callback, self._consume(self._read_buffer_size))
            self._read_callback = None
            return
        self._read_until_close = True
        self._streaming_callback = wrap(streaming_callback)
        self._add_io_state(self.io_loop.READ)

    def write(self, data, callback=None):
        assert isinstance(data, bytes_type)
        self._check_closed()
        if data:
            WRITE_BUFFER_CHUNK_SIZE = 128 * 1024
            if len(data) > WRITE_BUFFER_CHUNK_SIZE:
                for i in range(0, len(data), WRITE_BUFFER_CHUNK_SIZE):
                    self._write_buffer.append(data[i:i + WRITE_BUFFER_CHUNK_SIZE])
            else:
                self._write_buffer.append(data)
        self._write_callback = wrap(callback)
        if not self._connecting:
            self._handle_write()
            if self._write_buffer:
                self._add_io_state(self.io_loop.WRITE)
            self._maybe_add_error_listener()

    def set_close_callback(self, callback):
        self._close_callback = wrap(callback)

    def close(self):
        if self.socket is not None:
            if any(sys.exc_info()):
                self.error = sys.exc_info()[1]
            if self._read_until_close:
                callback = self._read_callback
                self._read_callback = None
                self._read_until_close = False
                self._run_callback(callback,
                                   self._consume(self._read_buffer_size))
            if self._state is not None:
                self.io_loop.remove_handler(self.socket.fileno())
                self._state = None
            self.socket.close()
            self.socket = None
        self._maybe_run_close_callback()

    def _maybe_run_close_callback(self):
        if (self.socket is None and self._close_callback and
            self._pending_callbacks == 0):
            cb = self._close_callback
            self._close_callback = None
            self._run_callback(cb)

    def reading(self):
        return self._read_callback is not None

    def writing(self):
        return bool(self._write_buffer)

    def closed(self):
        return self.socket is None

    def _handle_events(self, fd, events):
        if not self.socket:
            logging.warning("Got events for closed stream %d", fd)
            return
        try:
            if events & self.io_loop.READ:
                self._handle_read()
            if not self.socket:
                return
            if events & self.io_loop.WRITE:
                if self._connecting:
                    self._handle_connect()
                self._handle_write()
            if not self.socket:
                return
            if events & self.io_loop.ERROR:
                errno = self.socket.getsockopt(socket.SOL_SOCKET,
                                               socket.SO_ERROR)
                self.error = socket.error(errno, os.strerror(errno))
                self.io_loop.add_callback(self.close)
                return
            state = self.io_loop.ERROR
            if self.reading():
                state |= self.io_loop.READ
            if self.writing():
                state |= self.io_loop.WRITE
            if state == self.io_loop.ERROR:
                state |= self.io_loop.READ
            if state != self._state:
                assert self._state is not None, \
                    "shouldn't happen: _handle_events without self._state"
                self._state = state
                self.io_loop.update_handler(self.socket.fileno(), self._state)
        except Exception:
            logging.error("Uncaught exception, closing connection.",
                          exc_info=True)
            self.close()
            raise

    def _run_callback(self, callback, *args):
        def wrapper():
            self._pending_callbacks -= 1
            try:
                callback(*args)
            except Exception:
                logging.error("Uncaught exception, closing connection.",
                              exc_info=True)
                self.close()
                raise
            self._maybe_add_error_listener()
        with NullContext():
            self._pending_callbacks += 1
            self.io_loop.add_callback(wrapper)

    def _handle_read(self):
        try:
            try:
                self._pending_callbacks += 1
                while True:
                    if self._read_to_buffer() == 0:
                        break
            finally:
                self._pending_callbacks -= 1
        except Exception:
            logging.warning("error on read", exc_info=True)
            self.close()
            return
        if self._read_from_buffer():
            return
        else:
            self._maybe_run_close_callback()

    def _set_read_callback(self, callback):
        assert not self._read_callback, "Already reading"
        self._read_callback = wrap(callback)

    def _try_inline_read(self):
        if self._read_from_buffer():
            return
        self._check_closed()
        try:
            self._pending_callbacks += 1
            while True:
                if self._read_to_buffer() == 0:
                    break
                self._check_closed()
        finally:
            self._pending_callbacks -= 1
        if self._read_from_buffer():
            return
        self._maybe_add_error_listener()

    def _read_from_socket(self):
        try:
            chunk = self.socket.recv(self.read_chunk_size)
        except socket.error, e:
            if e.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                return None
            else:
                raise
        if not chunk:
            self.close()
            return None
        return chunk

    def _read_to_buffer(self):
        try:
            chunk = self._read_from_socket()
        except socket.error, e:
            logging.warning("Read error on %d: %s",
                            self.socket.fileno(), e)
            self.close()
            raise
        if chunk is None:
            return 0
        self._read_buffer.append(chunk)
        self._read_buffer_size += len(chunk)
        if self._read_buffer_size >= self.max_buffer_size:
            logging.error("Reached maximum read buffer size")
            self.close()
            raise IOError("Reached maximum read buffer size")
        return len(chunk)

    def _read_from_buffer(self):
        if self._streaming_callback is not None and self._read_buffer_size:
            bytes_to_consume = self._read_buffer_size
            if self._read_bytes is not None:
                bytes_to_consume = min(self._read_bytes, bytes_to_consume)
                self._read_bytes -= bytes_to_consume
            self._run_callback(self._streaming_callback,
                               self._consume(bytes_to_consume))
        if self._read_bytes is not None and self._read_buffer_size >= self._read_bytes:
            num_bytes = self._read_bytes
            callback = self._read_callback
            self._read_callback = None
            self._streaming_callback = None
            self._read_bytes = None
            self._run_callback(callback, self._consume(num_bytes))
            return True
        elif self._read_delimiter is not None:
            if self._read_buffer:
                while True:
                    loc = self._read_buffer[0].find(self._read_delimiter)
                    if loc != -1:
                        callback = self._read_callback
                        delimiter_len = len(self._read_delimiter)
                        self._read_callback = None
                        self._streaming_callback = None
                        self._read_delimiter = None
                        self._run_callback(callback,
                                           self._consume(loc + delimiter_len))
                        return True
                    if len(self._read_buffer) == 1:
                        break
                    _double_prefix(self._read_buffer)
        elif self._read_regex is not None:
            if self._read_buffer:
                while True:
                    m = self._read_regex.search(self._read_buffer[0])
                    if m is not None:
                        callback = self._read_callback
                        self._read_callback = None
                        self._streaming_callback = None
                        self._read_regex = None
                        self._run_callback(callback, self._consume(m.end()))
                        return True
                    if len(self._read_buffer) == 1:
                        break
                    _double_prefix(self._read_buffer)
        return False

    def _handle_connect(self):
        err = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err != 0:
            self.error = socket.error(err, os.strerror(err))
            logging.warning("Connect error on fd %d: %s",
                            self.socket.fileno(), errno.errorcode[err])
            self.close()
            return
        if self._connect_callback is not None:
            callback = self._connect_callback
            self._connect_callback = None
            self._run_callback(callback)
        self._connecting = False

    def _handle_write(self):
        while self._write_buffer:
            try:
                if not self._write_buffer_frozen:
                    _merge_prefix(self._write_buffer, 128 * 1024)
                num_bytes = self.socket.send(self._write_buffer[0])
                if num_bytes == 0:
                    self._write_buffer_frozen = True
                    break
                self._write_buffer_frozen = False
                _merge_prefix(self._write_buffer, num_bytes)
                self._write_buffer.popleft()
            except socket.error, e:
                if e.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    self._write_buffer_frozen = True
                    break
                else:
                    logging.warning("Write error on %d: %s",
                                    self.socket.fileno(), e)
                    self.close()
                    return
        if not self._write_buffer and self._write_callback:
            callback = self._write_callback
            self._write_callback = None
            self._run_callback(callback)

    def _consume(self, loc):
        if loc == 0:
            return b("")
        _merge_prefix(self._read_buffer, loc)
        self._read_buffer_size -= loc
        return self._read_buffer.popleft()

    def _check_closed(self):
        if not self.socket:
            raise IOError("Stream is closed")

    def _maybe_add_error_listener(self):
        if self._state is None and self._pending_callbacks == 0:
            if self.socket is None:
                self._maybe_run_close_callback()
            else:
                self._add_io_state(IOLoop.READ)

    def _add_io_state(self, state):
        if self.socket is None:
            return
        if self._state is None:
            self._state = IOLoop.ERROR | state
            with NullContext():
                self.io_loop.add_handler(
                    self.socket.fileno(), self._handle_events, self._state)
        elif not self._state & state:
            self._state = self._state | state
            self.io_loop.update_handler(self.socket.fileno(), self._state)


class SSLIOStream(IOStream):
    def __init__(self, *args, **kwargs):
        self._ssl_options = kwargs.pop('ssl_options', {})
        super(SSLIOStream, self).__init__(*args, **kwargs)
        self._ssl_accepting = True
        self._handshake_reading = False
        self._handshake_writing = False
        self._ssl_connect_callback = None

    def reading(self):
        return self._handshake_reading or super(SSLIOStream, self).reading()

    def writing(self):
        return self._handshake_writing or super(SSLIOStream, self).writing()

    def _do_ssl_handshake(self):
        try:
            self._handshake_reading = False
            self._handshake_writing = False
            self.socket.do_handshake()
        except ssl.SSLError, err:
            if err.args[0] == ssl.SSL_ERROR_WANT_READ:
                self._handshake_reading = True
                return
            elif err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                self._handshake_writing = True
                return
            elif err.args[0] in (ssl.SSL_ERROR_EOF,
                                 ssl.SSL_ERROR_ZERO_RETURN):
                return self.close()
            elif err.args[0] == ssl.SSL_ERROR_SSL:
                try:
                    peer = self.socket.getpeername()
                except:
                    peer = '(not connected)'
                logging.warning("SSL Error on %d %s: %s",
                                self.socket.fileno(), peer, err)
                return self.close()
            raise
        except socket.error, err:
            if err.args[0] in (errno.ECONNABORTED, errno.ECONNRESET):
                return self.close()
        else:
            self._ssl_accepting = False
            if self._ssl_connect_callback is not None:
                callback = self._ssl_connect_callback
                self._ssl_connect_callback = None
                self._run_callback(callback)

    def _handle_read(self):
        if self._ssl_accepting:
            self._do_ssl_handshake()
            return
        super(SSLIOStream, self)._handle_read()

    def _handle_write(self):
        if self._ssl_accepting:
            self._do_ssl_handshake()
            return
        super(SSLIOStream, self)._handle_write()

    def connect(self, address, callback=None):
        self._ssl_connect_callback = callback
        super(SSLIOStream, self).connect(address, callback=None)

    def _handle_connect(self):
        self.socket = ssl.wrap_socket(self.socket,
                                      do_handshake_on_connect=False,
                                      **self._ssl_options)
        super(SSLIOStream, self)._handle_connect()

    def _read_from_socket(self):
        if self._ssl_accepting:
            return None
        try:
            chunk = self.socket.read(self.read_chunk_size)
        except ssl.SSLError, e:
            if e.args[0] == ssl.SSL_ERROR_WANT_READ:
                return None
            else:
                raise
        except socket.error, e:
            if e.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                return None
            else:
                raise
        if not chunk:
            self.close()
            return None
        return chunk


def _double_prefix(deque):
    new_len = max(len(deque[0]) * 2,
                  (len(deque[0]) + len(deque[1])))
    _merge_prefix(deque, new_len)


def _merge_prefix(deque, size):
    if len(deque) == 1 and len(deque[0]) <= size:
        return
    prefix = []
    remaining = size
    while deque and remaining > 0:
        chunk = deque.popleft()
        if len(chunk) > remaining:
            deque.appendleft(chunk[remaining:])
            chunk = chunk[:remaining]
        prefix.append(chunk)
        remaining -= len(chunk)
    if prefix:
        deque.appendleft(type(prefix[0])().join(prefix))
    if not deque:
        deque.appendleft(b(""))


def doctests():
    import doctest
    return doctest.DocTestSuite()
import zlib


class ObjectDict(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value


class GzipDecompressor(object):
    def __init__(self):
        self.decompressobj = zlib.decompressobj(16 + zlib.MAX_WBITS)

    def decompress(self, value):
        return self.decompressobj.decompress(value)

    def flush(self):
        return self.decompressobj.flush()


def import_object(name):
    parts = name.split('.')
    obj = __import__('.'.join(parts[:-1]), None, None, [parts[-1]], 0)
    return getattr(obj, parts[-1])

if str is unicode:
    def b(s):
        return s.encode('latin1')
    bytes_type = bytes
else:
    def b(s):
        return s
    bytes_type = str


def raise_exc_info(exc_info):
    if isinstance(exc_info[1], exc_info[0]):
        raise exc_info[1], None, exc_info[2]
    else:
        raise exc_info[0], exc_info[1], exc_info[2]

import htmlentitydefs
import re
import sys
import urllib

try:
    bytes
except Exception:
    bytes = str

try:
    from urlparse import parse_qs  # Python 2.6+
except ImportError:
    from cgi import parse_qs

try:
    import json
    assert hasattr(json, "loads") and hasattr(json, "dumps")
    _json_decode = json.loads
    _json_encode = json.dumps
except Exception:
    try:
        import simplejson
        _json_decode = lambda s: simplejson.loads(_unicode(s))
        _json_encode = lambda v: simplejson.dumps(v)
    except ImportError:
        try:
            from django.utils import simplejson
            _json_decode = lambda s: simplejson.loads(_unicode(s))
            _json_encode = lambda v: simplejson.dumps(v)
        except ImportError:
            def _json_decode(s):
                raise NotImplementedError(
                    "A JSON parser is required, e.g., simplejson at "
                    "http://pypi.python.org/pypi/simplejson/")
            _json_encode = _json_decode


_XHTML_ESCAPE_RE = re.compile('[&<>"]')
_XHTML_ESCAPE_DICT = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}


def xhtml_escape(value):
    return _XHTML_ESCAPE_RE.sub(lambda match: _XHTML_ESCAPE_DICT[match.group(0)],
                                to_basestring(value))


def xhtml_unescape(value):
    return re.sub(r"&(#?)(\w+?);", _convert_entity, _unicode(value))


def json_encode(value):
    return _json_encode(recursive_unicode(value)).replace("</", "<\\/")


def json_decode(value):
    return _json_decode(to_basestring(value))


def squeeze(value):
    return re.sub(r"[\x00-\x20]+", " ", value).strip()


def url_escape(value):
    return urllib.quote_plus(utf8(value))

if sys.version_info[0] < 3:
    def url_unescape(value, encoding='utf-8'):
        if encoding is None:
            return urllib.unquote_plus(utf8(value))
        else:
            return unicode(urllib.unquote_plus(utf8(value)), encoding)

    parse_qs_bytes = parse_qs
else:
    def url_unescape(value, encoding='utf-8'):
        if encoding is None:
            return urllib.parse.unquote_to_bytes(value)
        else:
            return urllib.unquote_plus(to_basestring(value), encoding=encoding)

    def parse_qs_bytes(qs, keep_blank_values=False, strict_parsing=False):
        result = parse_qs(qs, keep_blank_values, strict_parsing,
                          encoding='latin1', errors='strict')
        encoded = {}
        for k, v in result.iteritems():
            encoded[k] = [i.encode('latin1') for i in v]
        return encoded


_UTF8_TYPES = (bytes, type(None))


def utf8(value):
    if isinstance(value, _UTF8_TYPES):
        return value
    assert isinstance(value, unicode)
    return value.encode("utf-8")

_TO_UNICODE_TYPES = (unicode, type(None))


def to_unicode(value):
    if isinstance(value, _TO_UNICODE_TYPES):
        return value
    assert isinstance(value, bytes)
    return value.decode("utf-8")

_unicode = to_unicode

if str is unicode:
    native_str = to_unicode
else:
    native_str = utf8

_BASESTRING_TYPES = (basestring, type(None))


def to_basestring(value):
    if isinstance(value, _BASESTRING_TYPES):
        return value
    assert isinstance(value, bytes)
    return value.decode("utf-8")


def recursive_unicode(obj):
    if isinstance(obj, dict):
        return dict((recursive_unicode(k), recursive_unicode(v)) for (k, v) in obj.iteritems())
    elif isinstance(obj, list):
        return list(recursive_unicode(i) for i in obj)
    elif isinstance(obj, tuple):
        return tuple(recursive_unicode(i) for i in obj)
    elif isinstance(obj, bytes):
        return to_unicode(obj)
    else:
        return obj

_URL_RE = re.compile(ur"""\b((?:([\w-]+):(/{1,3})|www[.])(?:(?:(?:[^\s&()]|&amp;|&quot;)*(?:[^!"#$%&'()*+,.:;<=>?@\[\]^`{|}~\s]))|(?:\((?:[^\s&()]|&amp;|&quot;)*\)))+)""")


def linkify(text, shorten=False, extra_params="",
            require_protocol=False, permitted_protocols=["http", "https"]):
    if extra_params and not callable(extra_params):
        extra_params = " " + extra_params.strip()

    def make_link(m):
        url = m.group(1)
        proto = m.group(2)
        if require_protocol and not proto:
            return url  # not protocol, no linkify

        if proto and proto not in permitted_protocols:
            return url  # bad protocol, no linkify

        href = m.group(1)
        if not proto:
            href = "http://" + href   # no proto specified, use http

        if callable(extra_params):
            params = " " + extra_params(href).strip()
        else:
            params = extra_params

        max_len = 30
        if shorten and len(url) > max_len:
            before_clip = url
            if proto:
                proto_len = len(proto) + 1 + len(m.group(3) or "")  # +1 for :
            else:
                proto_len = 0

            parts = url[proto_len:].split("/")
            if len(parts) > 1:
                url = url[:proto_len] + parts[0] + "/" + \
                        parts[1][:8].split('?')[0].split('.')[0]

            if len(url) > max_len * 1.5:  # still too long
                url = url[:max_len]

            if url != before_clip:
                amp = url.rfind('&')
                if amp > max_len - 5:
                    url = url[:amp]
                url += "..."

                if len(url) >= len(before_clip):
                    url = before_clip
                else:
                    params += ' title="%s"' % href

        return u'<a href="%s"%s>%s</a>' % (href, params, url)

    text = _unicode(xhtml_escape(text))
    return _URL_RE.sub(make_link, text)


def _convert_entity(m):
    if m.group(1) == "#":
        try:
            return unichr(int(m.group(2)))
        except ValueError:
            return "&#%s;" % m.group(2)
    try:
        return _HTML_UNICODE_MAP[m.group(2)]
    except KeyError:
        return "&%s;" % m.group(2)


def _build_unicode_map():
    unicode_map = {}
    for name, value in htmlentitydefs.name2codepoint.iteritems():
        unicode_map[name] = unichr(value)
    return unicode_map

_HTML_UNICODE_MAP = _build_unicode_map()
import logging
import urllib
import re



class HTTPHeaders(dict):
    def __init__(self, *args, **kwargs):
        dict.__init__(self)
        self._as_list = {}
        self._last_key = None
        if (len(args) == 1 and len(kwargs) == 0 and
            isinstance(args[0], HTTPHeaders)):
            for k, v in args[0].get_all():
                self.add(k, v)
        else:
            self.update(*args, **kwargs)


    def add(self, name, value):
        norm_name = HTTPHeaders._normalize_name(name)
        self._last_key = norm_name
        if norm_name in self:
            dict.__setitem__(self, norm_name, self[norm_name] + ',' + value)
            self._as_list[norm_name].append(value)
        else:
            self[norm_name] = value

    def get_list(self, name):
        norm_name = HTTPHeaders._normalize_name(name)
        return self._as_list.get(norm_name, [])

    def get_all(self):
        for name, list in self._as_list.iteritems():
            for value in list:
                yield (name, value)

    def parse_line(self, line):
        if line[0].isspace():
            new_part = ' ' + line.lstrip()
            self._as_list[self._last_key][-1] += new_part
            dict.__setitem__(self, self._last_key,
                             self[self._last_key] + new_part)
        else:
            name, value = line.split(":", 1)
            self.add(name, value.strip())

    @classmethod
    def parse(cls, headers):
        h = cls()
        for line in headers.splitlines():
            if line:
                h.parse_line(line)
        return h


    def __setitem__(self, name, value):
        norm_name = HTTPHeaders._normalize_name(name)
        dict.__setitem__(self, norm_name, value)
        self._as_list[norm_name] = [value]

    def __getitem__(self, name):
        return dict.__getitem__(self, HTTPHeaders._normalize_name(name))

    def __delitem__(self, name):
        norm_name = HTTPHeaders._normalize_name(name)
        dict.__delitem__(self, norm_name)
        del self._as_list[norm_name]

    def __contains__(self, name):
        norm_name = HTTPHeaders._normalize_name(name)
        return dict.__contains__(self, norm_name)

    def get(self, name, default=None):
        return dict.get(self, HTTPHeaders._normalize_name(name), default)

    def update(self, *args, **kwargs):
        for k, v in dict(*args, **kwargs).iteritems():
            self[k] = v

    def copy(self):
        return HTTPHeaders(self)

    _NORMALIZED_HEADER_RE = re.compile(r'^[A-Z0-9][a-z0-9]*(-[A-Z0-9][a-z0-9]*)*$')
    _normalized_headers = {}

    @staticmethod
    def _normalize_name(name):
        try:
            return HTTPHeaders._normalized_headers[name]
        except KeyError:
            if HTTPHeaders._NORMALIZED_HEADER_RE.match(name):
                normalized = name
            else:
                normalized = "-".join([w.capitalize() for w in name.split("-")])
            HTTPHeaders._normalized_headers[name] = normalized
            return normalized


def url_concat(url, args):
    if not args:
        return url
    if url[-1] not in ('?', '&'):
        url += '&' if ('?' in url) else '?'
    return url + urllib.urlencode(args)


class HTTPFile(ObjectDict):
    pass


def parse_body_arguments(content_type, body, arguments, files):
    if content_type.startswith("application/x-www-form-urlencoded"):
        uri_arguments = parse_qs_bytes(native_str(body))
        for name, values in uri_arguments.iteritems():
            values = [v for v in values if v]
            if values:
                arguments.setdefault(name, []).extend(values)
    elif content_type.startswith("multipart/form-data"):
        fields = content_type.split(";")
        for field in fields:
            k, sep, v = field.strip().partition("=")
            if k == "boundary" and v:
                parse_multipart_form_data(utf8(v), body, arguments, files)
                break
        else:
            logging.warning("Invalid multipart/form-data")


def parse_multipart_form_data(boundary, data, arguments, files):
    if boundary.startswith(b('"')) and boundary.endswith(b('"')):
        boundary = boundary[1:-1]
    final_boundary_index = data.rfind(b("--") + boundary + b("--"))
    if final_boundary_index == -1:
        logging.warning("Invalid multipart/form-data: no final boundary")
        return
    parts = data[:final_boundary_index].split(b("--") + boundary + b("\r\n"))
    for part in parts:
        if not part:
            continue
        eoh = part.find(b("\r\n\r\n"))
        if eoh == -1:
            logging.warning("multipart/form-data missing headers")
            continue
        headers = HTTPHeaders.parse(part[:eoh].decode("utf-8"))
        disp_header = headers.get("Content-Disposition", "")
        disposition, disp_params = _parse_header(disp_header)
        if disposition != "form-data" or not part.endswith(b("\r\n")):
            logging.warning("Invalid multipart/form-data")
            continue
        value = part[eoh + 4:-2]
        if not disp_params.get("name"):
            logging.warning("multipart/form-data value missing name")
            continue
        name = disp_params["name"]
        if disp_params.get("filename"):
            ctype = headers.get("Content-Type", "application/unknown")
            files.setdefault(name, []).append(HTTPFile(
                filename=disp_params["filename"], body=value,
                content_type=ctype))
        else:
            arguments.setdefault(name, []).append(value)


def _parseparam(s):
    while s[:1] == ';':
        s = s[1:]
        end = s.find(';')
        while end > 0 and (s.count('"', 0, end) - s.count('\\"', 0, end)) % 2:
            end = s.find(';', end + 1)
        if end < 0:
            end = len(s)
        f = s[:end]
        yield f.strip()
        s = s[end:]


def _parse_header(line):
    parts = _parseparam(';' + line)
    key = parts.next()
    pdict = {}
    for p in parts:
        i = p.find('=')
        if i >= 0:
            name = p[:i].strip().lower()
            value = p[i + 1:].strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
                value = value.replace('\\\\', '\\').replace('\\"', '"')
            pdict[name] = value
    return key, pdict

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
