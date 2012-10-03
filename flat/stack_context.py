
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
