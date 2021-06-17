import random
import requests
import time
from urllib3.exceptions import ProtocolError
import warnings

import plugins.XSStrike.core.config
from plugins.XSStrike.core.utils import converter, getVar
from plugins.XSStrike.core.log import setup_logger

logger = setup_logger(__name__)

warnings.filterwarnings('ignore')  # Disable SSL related warnings


def requester(url, data, headers, GET, delay, timeout,signal=None):
    if getVar('jsonData'):
        data = converter(data)
    elif getVar('path'):
        url = converter(data, url)
        data = []
        GET, POST = True, False
    time.sleep(delay)
    user_agents = ['Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36'
                   'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991']
    if 'User-Agent' not in headers:
        headers['User-Agent'] = random.choice(user_agents)
    elif headers['User-Agent'] == '$':
        headers['User-Agent'] = random.choice(user_agents)
    logger.debug('Requester url: {}'.format(url))
    logger.debug('Requester GET: {}'.format(GET))
    logger.debug_json('Requester data:', data)
    logger.debug_json('Requester headers:', headers)
    try:
        if GET:
            response = requests.get(url, params=data, headers=headers,
                                    timeout=timeout, verify=False, proxies=plugins.XSStrike.core.config.proxies)
        elif getVar('jsonData'):
            response = requests.post(url, json=data, headers=headers,
                                     timeout=timeout, verify=False, proxies=plugins.XSStrike.core.config.proxies)
        else:
            response = requests.post(url=url,data=data,headers=headers, verify=False,timeout=timeout,proxies={'http':'http://127.0.0.1:8080'})
            #response = requests.post(url, data=data, headers=headers,timeout=timeout, verify=False,proxies=plugins.XSStrike.core.config.proxies)
        return response
    except ProtocolError:
        logger.warning('WAF is dropping suspicious requests.')
        if signal == None:
            pass
        else:
            signal[str,str].emit('[-] WAF 丢弃了本次请求','red')
            signal[str, str].emit('[-] 扫描暂停，将在10分钟后继续', 'red')
        logger.warning('Scanning will continue after 10 minutes.')
        time.sleep(600)
