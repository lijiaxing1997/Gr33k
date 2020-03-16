import copy
import re

import plugins.XSStrike.core.config
from plugins.XSStrike.core.colors import green, end
from plugins.XSStrike.core.config import xsschecker
from plugins.XSStrike.core.filterChecker import filterChecker
from plugins.XSStrike.core.generator import generator
from plugins.XSStrike.core.htmlParser import htmlParser
from plugins.XSStrike.core.requester import requester
from plugins.XSStrike.core.log import setup_logger
import html

logger = setup_logger(__name__)


def crawl(scheme, host, main_url, form, blindXSS, blindPayload, headers, delay, timeout, encoding,signal):
    if form:
        for each in form.values():
            url = each['action']
            if url:
                if url.startswith(main_url):
                    pass
                elif url.startswith('//') and url[2:].startswith(host):
                    url = scheme + '://' + url[2:]
                elif url.startswith('/'):
                    url = scheme + '://' + host + url
                elif re.match(r'\w', url[0]):
                    url = scheme + '://' + host + '/' + url
                if url not in plugins.XSStrike.core.config.globalVariables['checkedForms']:
                    plugins.XSStrike.core.config.globalVariables['checkedForms'][url] = []
                method = each['method']
                GET = True if method == 'get' else False
                inputs = each['inputs']
                paramData = {}
                for one in inputs:
                    paramData[one['name']] = one['value']
                    for paramName in paramData.keys():
                        if paramName not in plugins.XSStrike.core.config.globalVariables['checkedForms'][url]:
                            plugins.XSStrike.core.config.globalVariables['checkedForms'][url].append(paramName)
                            paramsCopy = copy.deepcopy(paramData)
                            paramsCopy[paramName] = xsschecker
                            response = requester(
                                url, paramsCopy, headers, GET, delay, timeout)
                            occurences = htmlParser(response, encoding)
                            positions = occurences.keys()
                            efficiencies = filterChecker(
                                url, paramsCopy, headers, GET, delay, occurences, timeout, encoding)
                            vectors = generator(occurences, response.text)
                            if vectors:
                                for confidence, vects in vectors.items():
                                    try:
                                        payload = list(vects)[0]
                                        logger.vuln('Vulnerable webpage: %s%s%s' %
                                                    (green, url, end))
                                        logger.vuln('Vector for %s%s%s: %s' %
                                                    (green, paramName, end, payload))
                                        # #
                                        signal[str,str].emit('[+] 漏洞页面发现: %s' %url,'red')
                                        signal[str, str].emit('[+] 向量: %s : %s'  % (paramName,html.escape(payload)),'red')
                                        break
                                    except IndexError:
                                        pass
                            if blindXSS and blindPayload:
                                paramsCopy[paramName] = blindPayload
                                requester(url, paramsCopy, headers,
                                          GET, delay, timeout)
