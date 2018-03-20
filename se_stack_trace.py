#! /usr/bin/env python

"""SELinux stack trace

Usage:
  se_stack_trace.py [--source=<src_context>] [--target=<tgt_context>] [--pid=<pid]

Options:
  -h --help         Show this screen
  --source=<src>    Source context
  --target=<tgt>    Target context
  --pid=<pid>       Process to trace
"""

from docopt import docopt
import lib

if __name__ == "__main__":
    arguments = docopt(__doc__, version="SELinux stacktrace 0.1")
    if arguments['--source']==None and arguments['--target']==None:
        raise Exception("Must specify a source or a target!")

    source = arguments['--source']
    target = arguments['--target']
    pid = arguments['--pid']
    scid, tsid = None, None
    if source:
        scid = lib.get_sid(source)
    if target:
        tsid = lib.get_sid(target)

    lib.trace(scid, tsid, pid)
