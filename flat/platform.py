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
