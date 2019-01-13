import sys

import getopt


def get_env():
    opts, arg = getopt.getopt(sys.argv[1:], 'e:', '--env=')
    env = 'dev'
    for opt, arg in opts:
        if opt in ('-e', '--env'):
            env = arg
    return env
