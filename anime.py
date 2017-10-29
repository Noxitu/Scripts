"""Downloads anime from streaming sites"""
import sys
import inspect
import urllib.request
import re
import traceback
import os
from collections import namedtuple

DOWNLOAD_PATH = R"D:\Anime\{}"
log = lambda *a: None # pylint: disable=C0103

def debug(object):
    log('object:')
    for attr in dir(object):
        log('   ', attr, '=', getattr(object, attr))
    log()


class Color:
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    CYAN = '\033[36m'
    CLEAR = '\033[0m'

def get_cache_url(url):
    return R'http://webcache.googleusercontent.com/search?q=cache:{}'.format(url)

def parse_args(main, argv):
    """Parses argv into args and kwargs"""
    spec = inspect.getfullargspec(main)
    short_kwargs = {short: long for long, short in spec.annotations.items()}

    args = []
    kwargs = {}

    it = iter(argv) # pylint: disable=C0103

    try:
        options = True
        while True:
            arg = it.__next__()
            key = None
            value = None

            if options:
                if arg == '--':
                    options = False
                    continue

                if arg.startswith('--'):
                    if '=' in arg:
                        key, value = arg[2:].split('=', maxsplit=1)
                    else:
                        key = arg[2:]
                elif arg.startswith('-'):
                    key = short_kwargs[arg[1:]]

            if key is None:
                args.append(arg)
            else:
                if value is None:
                    if spec.kwonlydefaults.get(key) is False:
                        value = True
                    else:
                        value = it.__next__()

                kwargs[key] = value

    except StopIteration:
        pass

    return args, kwargs



#

class Opener(urllib.request.FancyURLopener):
    version = "Mozilla/5 "
    TIMEOUT = 10

    def __call__(self, url):
        response = self.open(url)
        try:
            return response.read()
        except:
            debug(response)
            raise

    def download(self, url, download_from=None):
        if download_from == 0:
            download_from = None

        #response = self.open(url)
        req = urllib.request.Request(url)

        if download_from is not None:
            req.add_header('Range', 'bytes={}-'.format(download_from))

        response = urllib.request.urlopen(req)

        if download_from is not None and response.getcode() != 206:
            raise Exception('No 206 response for range request')

        try:
            #print(response.getcode())
            #print(response.headers)
            total = int(response.headers['Content-Length'])
            chunk = total // 1000
        except Exception as e:
            log('"Content-Length" not found:')
            for line in traceback.format_exc().split('\n'):
                log('    {}'.format(line))

            total = None
            chunk = 512*1024

        read = 0

        if download_from is not None:
            read += download_from
            total += download_from        

        while True:
            ret = response.read(chunk)
            if not ret:
                break
            read += len(ret)
            yield ret

            if total is not None:
                sys.stdout.write('\rProgress: {:.1f}%'.format(100*read/total))
            else:
                sys.stdout.write('\rProgress: {} bytes'.format(read))
            sys.stdout.flush()

        sys.stdout.write('\n')
#

class NotFound(Exception): pass
def find(data, *queries):
    result = []
    for query in queries:
        match = re.search(query, data)
        if match is None:
            log('Did not find:\n    {}\n'.format(query))
            raise NotFound()
        log('Found a match:\n    {}'.format(match.group(0).decode('utf8')))
        result.append(match)
    if len(result) == 1:
        return result[0]
    return result

def get_url(match):
    data = match.groupdict()
    if 'url' in data:
        return data['url'].decode('utf8')
    if 'escaped_url' in data:
        return data['escaped_url'].decode('unicode_escape')

def get_extension(url):
    ext = re.search(R'\.(?P<ext>[0-9a-zA-Z]+)(?:\?.*)?$', url)
    if ext:
        return ext.group('ext')

class Handler:
    Handler = namedtuple('Hadler', ['name', 'regex', 'handle'])

    def __init__(self):
        self.handlers = []

    def create(self, name, regex):
        def decorator(call):
            self.handlers.append(self.Handler(name, re.compile(regex), call))
            return call
        return decorator

    def __call__(self, url, opener, **kwargs):
        result = {}
        for handler in self.handlers:
            if handler.regex.match(url):
                log('Found handler "{}" for url:\n    {}'.format(handler.name, url))
                for key, value in handler.handle(url, opener, **kwargs):
                    result[key] = value

                if 'url' in result:
                    return result

        return result

#
handler = Handler() # pylint: disable=C0103

@handler.create('VideoWing', R'^http://videowing.me/.*$|^http://videowing.gogoanime.to.*$')
@handler.create('EasyVideo', R'^http://easyvideo.me/.*$')
def videowing(url, opener):
    query = Rb'var video_links = \{.*,"link":"(?P<escaped_url>http[^"]+)".*};'
    try:
        m = find(opener(url), query)
        yield 'url', get_url(m).replace('\\/', '/')
    except NotFound:
        log('    Not found...')

@handler.create('estream', R'^https://estream.to/.*$')
def estream(url, opener):
    data = opener(url)
    sources = re.findall(Rb"<source src=\"(?P<url>.*?)\" type='video/mp4' .*? res='(?P<res>\d+)x(\d+)' />", data)

    if sources:
        log('Found sources')
        for url, res, res2 in sources:
            log('    {} ({}x{})'.format(url.decode('utf-8'), res.decode('utf-8'), res2.decode('utf-8')))
        sources.sort(key=lambda m : m[1])
        yield 'url', sources[-1][0].decode('utf-8')
        yield 'ext', 'mp4'
        return

@handler.create('vidstreaming', R'^https://vidstreaming.io/embed.php.*$')
def vidstreaming(url, opener):
    data = opener(url)
    sources = re.findall(Rb"<source src='(?P<url>.*?)' type='video/mp4' label='(?P<res>\d+)'/>", data)
    if sources:
        sources.sort(key=lambda m : m[1])
        yield 'url', sources[-1][0].decode('utf-8')
        yield 'ext', 'mp4'
        return

    iframes = re.findall(Rb'<iframe [^>]*src="([^"]+)', data)
    log('Found iframes: ')
    for src in iframes:
        log('    {}'.format(src.decode('utf-8')))

    for src in iframes:
        result = handler(src.decode('utf-8'), opener)

        if 'url' in result:
            for key, value in result.items():
                yield key, value
            return


@handler.create('AnimePlus.tv', R'^http://www\.animeplus\.tv/.*$')
def animeplus(url, opener, part = None):
    query_title = Rb'<title>(?P<title>.*?)(?:English Sub)?</title>'

    data = opener(url)
    m = find(data, query_title)
    yield 'title', m.group('title').decode('utf-8').strip()

    iframes = re.findall(Rb'<iframe [^>]*src="([^"]+)', data)
    log('Found iframes: ')
    for src in iframes:
        log('    {}'.format(src.decode('utf-8')))

    part_no = 1
    for src in iframes:
        result = handler(src.decode('utf-8'), opener)

        if 'url' in result:
            if part is not None and part_no < int(part):
                part_no += 1
                continue

            for key, value in result.items():
                yield key, value

            return

@handler.create('GoGoAnime', R'^https://ww2.gogoanime.io/.*$')
def gogoanime(url, opener):
    data = opener(url)

    query_title = Rb'<title>Watch (?P<title>.*?) English Subbedat Gogoanime</title>'

    m = find(data, query_title)
    yield 'title', m.group('title').decode('utf-8').strip()

    iframes = re.findall(Rb'<iframe [^>]*src="([^"]+)', data)
    log('Found iframes: ')
    for src in iframes:
        log('    {}'.format(src.decode('utf-8')))

    for src in iframes:
        result = handler(src.decode('utf-8'), opener)

        if 'url' in result:
            for key, value in result.items():
                yield key, value
            return

@handler.create('cda.pl', R'^https://www.cda.pl/video/.*$')
def cda(url, opener):
    data = opener(url)
    try:
        if 'wersja=' not in url:
            res = re.findall(Rb'\?wersja=(\d+)p', data)
            res = list(map(int, res))

            url += '&' if '?' in url else '?'
            res = max(res)
            url += 'wersja={}p'.format(res)
            data = opener(url)
            yield 'wersja', '{}p'.format(res)
    except:
        pass

    query_title = Rb'<title>(.*?) - wideo w cda.pl</title>'
    query_video = Rb'"file":"(.*?)"'

    title_match, video_match = find(data, query_title, query_video)

    def decode_character(c):
        rot13 = lambda c, zero : (c - zero + 13)%26 + zero
        if 'a' <= c <= 'z':
            return chr(rot13(ord(c), ord('a')))
        if 'A' <= c <= 'Z':
            return chr(rot13(ord(c), ord('A')))
        return c

    video_url = video_match.group(1).decode('utf-8').replace('\\/', '/')
    log('Discovered encoded url:\n    {}'.format(video_url))
    video_url = ''.join(decode_character(c) for c in video_url)
    video_url = video_url[:-7] + video_url[-4:]

    yield 'title', title_match.group(1).decode('utf-8').strip()
    yield 'url', video_url


def main(*urls, verbose: 'v' = False, part = None):
    """Entry point"""
    global log # pylint: disable=C0103, W0603
    if verbose:
        log = print

    opener = Opener()
    for url in urls:
        try:
            video = handler(url, opener, part = part)
            video['input_url'] = '{}{}{}'.format(Color.CYAN, url, Color.CLEAR)

            if 'url' in video and 'ext' not in video:
                video['ext'] = get_extension(video['url'])

            if part is not None:
                video['part'] = 'Part #' + part

            print('Video information:')
            for key, value in video.items():
                print('    {} = {}'.format(key, value))

            if {'title', 'url'} < video.keys():
                title = video['title'].replace(':', ';').replace('/', ';')

                if part is not None:
                    title += ' - Part ' + part

                output_path = DOWNLOAD_PATH.format(title)
                if video['ext'] is not None:
                    output_path += '.' + video['ext']

                try:
                    statinfo = os.stat(output_path)
                    downloaded_size = statinfo.st_size
                except FileNotFoundError:
                    downloaded_size = None

                with open(output_path, 'ab') as output_file:
                    for chunk in opener.download(video['url'], download_from=downloaded_size):
                        output_file.write(chunk)
                print('{}Downloaded.{}'.format(Color.GREEN, Color.CLEAR))
                print()
            else:
                print('{}Not enough information to download video!{}'.format(Color.RED, Color.CLEAR))
                print()
        except Exception as e:
            traceback.print_exc()

if __name__ == '__main__':
    try:
        ARGS, KWARGS = parse_args(main, sys.argv[1:])
    except:
        help(main)
        raise

    main(*ARGS, **KWARGS)
