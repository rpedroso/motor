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
