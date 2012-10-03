

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
