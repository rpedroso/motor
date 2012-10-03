Motor
=====

MoTor - Mo(nolithic) Tor(nado)

It is an experimental monolithic build of tornado HTTPServer
In other words is tornado HTTPServer in one big py file.
Its not the tornado full suite.


Build instrutions
=================

    mkdir -p motor/flat
    cd motor/flat

1. strip comments, docstrings and tornado package imports
    python b.py /path/to/tornado/httpserver.py >httpserver.py

2. edit httpserver.py and remove the __future__ imports.
   do the same to the following files:
    - escape.py
    - httputil.py
    - ioloop.py
    - iostream.py
    - netutil.py
    - platform/common.py -> platform_common.py (1)
    - platform/windows.py -> platform_windows.py (1)
    - platform/posix.py -> platform_posix.py (1)
    - process.py
    - stack_context.py
    - util.py
    - wsgi.py (2)


    (1) platform_common.py and platform_windows.py go into a new file
        platform.py and wrap them into an `if os.name == 'nt'`

        platform_posix.py goes to the `else` block of the above `if`.

    (2) In wsgi.py delete the classes WSGIApplication and HTTPRequest.
        Change tornado.version to MOTOR_VERSION and
        add into 0.py:

            MOTOR_VERSION = '2.4.0.0'


3. add that __future__ imports line into new file 0.py.

4. then concatenate all the files:

    sh cat_all.sh

   We should have a new ../motor.py

   This motor.py is not ready yet...

   ...with some trial and error all flat/* files should be manually tweaked
   due tue some classes/defs references, for eg in httpserver.py we have:
       self._header_callback = stack_context.wrap(self._on_headers)
   should be changed to:
       self._header_callback = wrap(self._on_headers)

   So tweak, regenerate motor.py until everythong is ok.


Tests files
===========

t.py - A hello world

t_wsgi.py - A WSGI hello world

t_web2py.py - run web2py

    python t_web2py.py /path/to/web2py



Some benchmarks
===============

Note: I have an old laptop so your results will be better, I'm sure :)

My CPU's:

    model name : Intel(R) Pentium(R) Dual  CPU  T2310  @ 1.46GHz
    cpu MHz    : 1467.000
    cache size : 1024 KB
    bogomips   : 2925.98


With Rocket:
------------

    ab -c 100 -n 500 http://localhost:8888/welcome/default/index

    Server Software:        Rocket
    Server Hostname:        localhost
    Server Port:            8000

    Document Path:          /welcome/default/index
    Document Length:        11687 bytes

    Concurrency Level:      100
    Time taken for tests:   28.371 seconds
    Complete requests:      500
    Failed requests:        0
    Write errors:           0
    Total transferred:      6053500 bytes
    HTML transferred:       5843500 bytes
    Requests per second:    17.62 [#/sec] (mean)
    Time per request:       5674.182 [ms] (mean)
    Time per request:       56.742 [ms] (mean, across all concurrent requests)
    Transfer rate:          208.37 [Kbytes/sec] received

    Connection Times (ms)
                  min  mean[+/-sd] median   max
    Connect:        0    2   3.9      0      13
    Processing:   218 5160 1262.8   5602    6113
    Waiting:      216 5158 1262.9   5599    6112
    Total:        230 5162 1259.2   5602    6114

    Percentage of the requests served within a certain time (ms)
      50%   5602
      66%   5671
      75%   5746
      80%   5809
      90%   5920
      95%   5977
      98%   6006
      99%   6033
     100%   6114 (longest request)


With monolithic Tornado:
------------------------

    ab -c 100 -n 500 http://localhost:8888/welcome/default/index

    Server Software:        TornadoServer/2.4.0.0
    Server Hostname:        localhost
    Server Port:            8888

    Document Path:          /welcome/default/index
    Document Length:        11687 bytes

    Concurrency Level:      100
    Time taken for tests:   12.609 seconds
    Complete requests:      500
    Failed requests:        0
    Write errors:           0
    Total transferred:      6023500 bytes
    HTML transferred:       5843500 bytes
    Requests per second:    39.66 [#/sec] (mean)
    Time per request:       2521.749 [ms] (mean)
    Time per request:       25.217 [ms] (mean, across all concurrent requests)
    Transfer rate:          466.53 [Kbytes/sec] received

    Connection Times (ms)
                  min  mean[+/-sd] median   max
    Connect:        0    1   2.5      0      11
    Processing:    52 2246 958.8   2339    4212
    Waiting:       52 2245 958.8   2338    4211
    Total:         57 2247 957.7   2341    4212

    Percentage of the requests served within a certain time (ms)
      50%   2341
      66%   2654
      75%   2874
      80%   3022
      90%   3591
      95%   3865
      98%   4028
      99%   4095
     100%   4212 (longest request)

