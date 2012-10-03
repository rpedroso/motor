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

