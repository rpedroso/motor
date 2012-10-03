
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
