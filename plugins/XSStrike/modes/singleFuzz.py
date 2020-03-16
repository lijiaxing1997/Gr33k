import copy
from urllib.parse import urlparse

from plugins.XSStrike.core.colors import green, end
from plugins.XSStrike.core.config import xsschecker
from plugins.XSStrike.core.fuzzer import fuzzer
from plugins.XSStrike.core.requester import requester
from plugins.XSStrike.core.utils import getUrl, getParams
from plugins.XSStrike.core.wafDetector import wafDetector
from plugins.XSStrike.core.log import setup_logger

logger = setup_logger(__name__)


def singleFuzz(target, paramData, encoding, headers, delay, timeout):
    GET, POST = (False, True) if paramData else (True, False)
    # If the user hasn't supplied the root url with http(s), we will handle it
    if not target.startswith('http'):
        try:
            response = requester('https://' + target, {},
                                 headers, GET, delay, timeout)
            target = 'https://' + target
        except:
            target = 'http://' + target
    logger.debug('Single Fuzz target: {}'.format(target))
    host = urlparse(target).netloc  # Extracts host out of the url
    logger.debug('Single fuzz host: {}'.format(host))
    url = getUrl(target, GET)
    logger.debug('Single fuzz url: {}'.format(url))
    params = getParams(target, paramData, GET)
    logger.debug_json('Single fuzz params:', params)
    if not params:
        logger.error('No parameters to test.')
        quit()
    WAF = wafDetector(
        url, {list(params.keys())[0]: xsschecker}, headers, GET, delay, timeout)
    if WAF:
        logger.error('WAF detected: %s%s%s' % (green, WAF, end))
    else:
        logger.good('WAF Status: %sOffline%s' % (green, end))

    for paramName in params.keys():
        logger.info('Fuzzing parameter: %s' % paramName)
        paramsCopy = copy.deepcopy(params)
        paramsCopy[paramName] = xsschecker
        fuzzer(url, paramsCopy, headers, GET,
               delay, timeout, WAF, encoding)
