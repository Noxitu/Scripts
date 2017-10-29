import os
import sys

SUFIXES = ['', '.py']

def find_path(path):
    paths = [path+sufix for sufix in SUFIXES]

    for path in paths:
        fullpath = os.path.abspath(path)
        if os.path.exists(fullpath):
            return fullpath

    basedir = os.path.dirname(__file__)
    for path in paths:
        fullpath = os.path.abspath(os.path.join(basedir, path))
        if os.path.exists(fullpath):
            return fullpath

    raise Exception('Could not find file')

def main(path, alias=None):
    path = find_path(path)
    print('@python "{}" %*'.format(path))

if __name__ == '__main__':
    main(sys.argv[1])