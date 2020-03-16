import copy
from urllib.parse import urlparse, unquote

from plugins.XSStrike.core.arjun import arjun
from plugins.XSStrike.core.checker import checker
from plugins.XSStrike.core.colors import end, green, que
import plugins.XSStrike.core.config
from plugins.XSStrike.core.config import xsschecker, minEfficiency
from plugins.XSStrike.core.dom import dom
from plugins.XSStrike.core.filterChecker import filterChecker
from plugins.XSStrike.core.generator import generator
from plugins.XSStrike.core.htmlParser import htmlParser
from plugins.XSStrike.core.requester import requester
from plugins.XSStrike.core.utils import getUrl, getParams
from plugins.XSStrike.core.wafDetector import wafDetector
from plugins.XSStrike.core.log import setup_logger
import html

logger = setup_logger(__name__)


def scan(payload_signal,signal,target, paramData, encoding, headers, delay, timeout, skipDOM, find, skip):
    GET, POST = (False, True) if paramData else (True, False)
    # If the user hasn't supplied the root url with http(s), we will handle it
    if not target.startswith('http'):
        try:
            response = requester('https://' + target, {},
                                 headers, GET, delay, timeout)
            target = 'https://' + target
        except:
            target = 'http://' + target
    logger.debug('Scan target: {}'.format(target))
    response = requester(target, {}, headers, GET, delay, timeout).text

    if not skipDOM:
        logger.run('Checking for DOM vulnerabilities')
        signal[str, str].emit('[+] 检测DOM XSS', 'green')
        highlighted = dom(response)
        if highlighted:
            logger.good('Potentially vulnerable objects found')
            signal[str, str].emit('[+] 发现DOM XSS', 'red')
            logger.red_line(level='good')
            for line in highlighted:
                logger.no_format(line, level='good')
                signal[str, str].emit('[+] %s' % line, 'red')
            logger.red_line(level='good')
    host = urlparse(target).netloc  # Extracts host out of the url
    logger.debug('Host to scan: {}'.format(host))
    url = getUrl(target, GET)
    logger.debug('Url to scan: {}'.format(url))
    params = getParams(target, paramData, GET)
    logger.debug_json('Scan parameters:', params)
    if find:
        params = arjun(url, GET, headers, delay, timeout)
    if not params:
        logger.error('No parameters to test.')
        quit()
    WAF = wafDetector(
        url, {list(params.keys())[0]: xsschecker}, headers, GET, delay, timeout)
    if WAF:
        # logger.error('WAF detected: %s%s%s' % (green, WAF, end))
        signal[str, str].emit('[+] WAF 状态: 被保护 -> %s'%(WAF), 'red')
    else:
        # logger.good('WAF Status: %sOffline%s' % (green, end))
        signal[str,str].emit('[+] WAF 状态: 无WAF','red')

    for paramName in params.keys():
        paramsCopy = copy.deepcopy(params)
        # logger.info('Testing parameter: %s' % paramName)
        signal[str, str].emit('[+] 测试参数: %s' % paramName, 'green')
        if encoding:
            paramsCopy[paramName] = encoding(xsschecker)
        else:
            paramsCopy[paramName] = xsschecker
        response = requester(url, paramsCopy, headers, GET, delay, timeout)
        occurences = htmlParser(response, encoding)
        positions = occurences.keys()
        logger.debug('Scan occurences: {}'.format(occurences))
        if not occurences:
            # logger.error('No reflection found')
            signal[str, str].emit('[-] 没有发现反射点', 'green')
            continue
        else:
            # logger.info('Reflections found: %i' % len(occurences))
            signal[str, str].emit('[+] 发现反射点: %i' % len(occurences), 'red')
        logger.run('Analysing reflections')
        signal[str, str].emit('[+] 分析反射点', 'green')
        efficiencies = filterChecker(
            url, paramsCopy, headers, GET, delay, occurences, timeout, encoding)
        logger.debug('Scan efficiencies: {}'.format(efficiencies))
        # logger.run('Generating payloads')
        signal[str, str].emit('[+] 创建payload', 'green')
        vectors = generator(occurences, response.text)
        total = 0
        for v in vectors.values():
            total += len(v)
        if total == 0:
            logger.error('No vectors were crafted.')
            continue
        logger.info('Payloads generated: %i' % total)
        signal[str, str].emit('[+] payload已创建: %i'% total, 'green')
        progress = 0
        for confidence, vects in vectors.items():
            for vect in vects:
                if plugins.XSStrike.core.config.wait == 1:
                    return
                if plugins.XSStrike.core.config.globalVariables['path']:
                    vect = vect.replace('/', '%2F')
                loggerVector = vect
                progress += 1
                logger.run('Progress: %i/%i\r' % (progress, total))
                if not GET:
                    vect = unquote(vect)
                efficiencies = checker(
                    url, paramsCopy, headers, GET, delay, vect, positions, timeout, encoding)
                if not efficiencies:
                    for i in range(len(occurences)):
                        efficiencies.append(0)
                bestEfficiency = max(efficiencies)
                if bestEfficiency == 100 or (vect[0] == '\\' and bestEfficiency >= 95):
                    logger.red_line()
                    signal[str, str].emit('-'*50, 'red')
                    logger.good('Payload: %s' % loggerVector)
                    payload_signal[str].emit(paramName + ': ' + html.escape(loggerVector))
                    signal[str, str].emit('[+] payload: %s' % html.escape(loggerVector), 'red')
                    logger.info('Efficiency: %i' % bestEfficiency)
                    signal[str, str].emit('[+] 效率: %i' % bestEfficiency, 'red')
                    logger.info('Confidence: %i' % confidence)
                    signal[str, str].emit('[+] 成功率: %i' % confidence, 'red')
                    if not skip:
                        choice = input(
                            '%s Would you like to continue scanning? [y/N] ' % que).lower()
                        if choice != 'y':
                            quit()
                elif bestEfficiency > minEfficiency:
                    logger.red_line()
                    signal[str, str].emit('-' * 50, 'red')
                    logger.good('Payload: %s' % loggerVector)
                    payload_signal[str].emit(paramName + ': ' + html.escape(loggerVector))
                    signal[str, str].emit('[+] payload: %s' % html.escape(loggerVector), 'red')
                    logger.info('Efficiency: %i' % bestEfficiency)
                    signal[str, str].emit('[+] 效率: %i' % bestEfficiency, 'red')
                    logger.info('Confidence: %i' % confidence)
                    signal[str, str].emit('[+] 成功率: %i' % confidence, 'red')
        logger.no_format('')
