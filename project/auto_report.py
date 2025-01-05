""" Functions related to auto-reporting. """

import datetime
import ipaddress
import json
import logging
import requests
import re
import sqlite3
from flask import request, current_app
from dateutil.parser import parse
from urllib.parse import urlparse

requests_db = 'bots.db'

def get_real_ip():
    """ Get client's IP from behind Nginx/Cloudflare. """
    # Use the CF IPv6 header first if present. CF adds an IPv4 header if using its
    # pseudo-IPv6 function; in that case the IPv4 will be the proxy's IP, not the client's.
    if 'Cf-Connecting-Ipv6' in request.headers:
        real_ip = request.headers.get('Cf-Connecting-Ipv6')
    elif 'Cf-Connecting-Ip' in request.headers:
        real_ip = request.headers.get('Cf-Connecting-Ip')
    elif 'X-Real-Ip' in request.headers:
        real_ip = request.headers.get('X-Real-Ip')
    elif 'X-Forwarded-For' in request.headers:
        real_ip = request.headers.get('X-Forwarded-For')
    else:
        real_ip = request.remote_addr
    return real_ip

def exempt_from_reporting(_ip):
    """ Check whether the IP is within any of configured EXEMPT_SUBNETS. """
    if not current_app.config.get('EXEMPT_SUBNETS'):
        return False #If no subnets configured, then not exempt.
    else:
        EXEMPT_SUBNETS = current_app.config.get('EXEMPT_SUBNETS')
        _ip_addr = ipaddress.ip_address(_ip)
        return any(_ip_addr in ipaddress.ip_network(exempt_subnet) for exempt_subnet in EXEMPT_SUBNETS)

def already_reported(_ip):
    """ Return True if IP has been reported within past 15 minutes. """
    ip_to_check = _ip
    current_time = datetime.datetime.now().astimezone().replace(microsecond=0).isoformat()
    rate_limit_delta = datetime.timedelta(minutes=15)

    #Retrieve timestamp of the last hit from given ip that was reported
    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql_query = """SELECT time FROM bots
            WHERE remoteaddr LIKE ? AND reported = 1
            ORDER BY id DESC
            LIMIT 1;"""
        data_tuple = (ip_to_check,)
        c.execute(sql_query, data_tuple)
        last_reported_hit = c.fetchone()
        c.close()
    conn.close()
    
    #Compare timestamp to current time, if any hits found
    if last_reported_hit:
        last_reported_time = last_reported_hit['time']
        #logging.debug(f'last reported time: {last_reported_time}')
        current_time_parsed = parse(current_time)
        last_reported_time_parsed = parse(last_reported_time)
        time_difference = current_time_parsed - last_reported_time_parsed
        #logging.debug(f'Difference: {time_difference}')
        if abs(time_difference) < rate_limit_delta:
            logging.debug('IP already reported in past 15 minutes; not reporting.')
            return True
        else:
            logging.debug('Not already reported.')
            return False
    return False

def submit_report(report_comment, report_categories):
    """ Submit the report. Usage: reported = submit_report(report_comment, report_categories) """
    API_URL = 'https://api.abuseipdb.com/api/v2/report'
    params = {
            'ip': get_real_ip(),
            'categories': report_categories,
            'comment': report_comment,
            'timestamp': datetime.datetime.now().astimezone().replace(microsecond=0).isoformat(),
    }
    headers = {
            'Accept': 'application/json',
            'Key': current_app.config["ABUSEIPDB"],
    }
    response = requests.post(url = API_URL, headers = headers, params = params)
    decoded_response = json.loads(response.text)

    # API response will contain an 'errors' key if any issues - rate limit, sent bad data, etc.
    if 'errors' in decoded_response:
        #logging.error(error['detail'] for error in decoded_response['errors'] if 'detail' in error)
        for error in decoded_response['errors']:
            logging.error(error['detail'])
        reported = 0
    else:
        reported = 1
    return reported

# BEGIN RULES

ENV_PROBE_PATHS = [
    '.env', #The big winner
    '.htaccess', '.htpasswd',
    '/config',
    '/conf',
    '.conf',
    '/admin',
    '.git', '.svn', #version control
    '/.aws',
    'backend',
    'phpinfo',
    'Util/PHP/eval-stdin.php', #Seen a few versions, mostly /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
    'echo.php',
    '/api',
    '/system/deviceinfo', #seen as /system/deviceinfo
    '/public',
    '/src',
    '/app',
    '/www',
    '/vendor',
    '/laravel',
    '/storage', '/protected', # seen as /storage/protected - Redlion RAS
    '/library',
    '/auth', #will also catch /authn
    '/login',
    '/logon',
    '/session',
    '/database',
    '/scripts',
    '/99vt', '/99vu', '/gate.php', '/aaaaaaaaaaaaaaaaaaaaaaaaaqr', #some misc malware
    '/form.html', 'upl.php', 'info.php', '/bundle.js', '/files/', #Usually probed together
    '/whyareugay', # Some malware maybe? Been seeing it from the same couple subnets
    '/log/',
    '/jquery.js',
    '/jquery-3.3.1.min.js', #seen this a bunch of times now
    '/jquery-1.12.4.min.js', #Lots of this too, probing for vulnerable versions.
    'jquery',
    '.json',
    '/server-status',
    '/.DS_Store',
    '/login.action', #Atlassian?
    '/_/;/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.properties', #/s/43e26313e21323e2430313/_/;/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.properties
]

def is_env_probe(request):
    """ Returns True if path contains any of target strings. Only catch GET for this rule.
    Some environment/config probes I see often. """
    path = request.path
    method = request.method
    ENV_PROBE_METHODS = ['GET', 'HEAD']
    if method in ENV_PROBE_METHODS:
        return any(target in path.lower() for target in ENV_PROBE_PATHS)
    return False

def is_php_easter_egg(request):
    """ True if query string contains any of the PHP easter egg queries.
    I see these usually alongside nmap HTTP scans.
    PHP has several known “easter eggs” which are packaged with PHP versions prior to 5.5. """
    PHP_EASTER_EGGS = [
        '=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000', #PHP Credits
        '=PHPE9568F36-D428-11d2-A769-00AA001ACF42', #PHP Version Logo
        '=PHPE9568F35-D428-11d2-A769-00AA001ACF42', #Zend Logo
        '=PHPE9568F34-D428-11d2-A769-00AA001ACF42', #PHP Logo
    ]
    if request.query_string is not None:
        query_string_decoded = request.query_string.decode(errors='replace')
        return any(target.lower() in query_string_decoded.lower() for target in PHP_EASTER_EGGS)
    return False

def is_phpmyadmin_probe(request):
    """ Probing for PHPMyAdmin instances. """
    path = request.path
    PMA_PROBE_PATHS = ['phpmyadmin', '/pma', '/mysql/', '/sqladmin/', '/mysqlmanager/', '/myadmin/']
    return any(target in path.lower() for target in PMA_PROBE_PATHS)

def is_cgi_probe(request):
    """ Anything targeting CGI scripts. """
    path = request.path
    CGI_PROBE_PATHS = [
        '.cgi',
        '.cc',
        '/cgi-bin',
        ]
    return any(target in path.lower() for target in CGI_PROBE_PATHS)

def is_injection_attack(request):
    """ Command injection attempts in the path+query, POSTed data, or header values. """
    path_full = request.full_path
    #posted_data_decoded = request.get_data(as_text=True)
    posted_data_decoded = request.get_data().decode('utf-8', errors='replace')
    header_values_joined = ''.join(request.headers.values())
    INJECTION_SIGNATURES = [
        ';sh',
        '|sh',
        '.sh;',
        'sh+',
        '.sh%20%7C', #i.e. curl example.sh | something
        '/tmp;',
        '+/tmp',
        '%2Ftmp',
        'file=', # might need to adjust this one, could hit on a real query
        ';wget',
        'wget+',
        '&wget',
        'wget http', #may be http or https
        '`', '%60', #Everything containing ` has been injection
        ';chmod',
        'cd+',
        ';rm -rf', #formatted with spaces in headers injection
        'rm+-rf',
        ' && ',
        '<?php', 'shell_exec', 'base64_decode', 'base64-decode', #php injection
        '/bin/bash',
        'chmod 777',
        'eval(', 'echo(',
        '||',
        # ';', #semicolon in the path would be injection but not headers
    ]
    # Check for signatures in the path+query, POSTed data, and headers
    if (
        any(target in path_full.lower() for target in INJECTION_SIGNATURES)
        or any(target in posted_data_decoded.lower() for target in INJECTION_SIGNATURES)
        or any(target in header_values_joined.lower() for target in INJECTION_SIGNATURES)
    ):
        return True
    else:
        return False

def is_path_traversal(request):
    """ Path traversal. """
    PATH_TRAVERSAL_SIGS = [
        r'\.\./',
        r'%2e%2e%2f',
        r'\.\.%2f',
    ]
    pattern = '|'.join(PATH_TRAVERSAL_SIGS)
    regex = re.compile(pattern, re.IGNORECASE)
    #return bool(regex.search(request.full_path))

    # Check the path
    if regex.search(request.full_path):
        return True
    # Check the body
    if request.method == 'POST':
        body = request.get_data(as_text=True)
        if regex.search(body):
            return True
    # If no signatures found in either, return False
    return False

MISC_SOFTWARE_PROBE_PATHS = [
    '/adminer',
    '/ReportServer', #Microsoft SQL report service
    '/boaform/admin/formLogin', #/boaform/admin/formLogin = Some OEM Fiber gear. Usually seen POSTing `username=admin&psd=Feefifofum`
    '/actuator', #/actuator/health - Sping Boot health check
    '/druid', #Apache Druid
    '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', #phpunit CVE-2017-9841 = POST to /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
    '/geoserver/web', '/webui', #Cisco ios xe - recent vuln being exploited - usually seen as /webui/logoutconfirm.html?logon_hash=1
    '/mailchimp', # mailchimp probes
    '/portal', '/redlion', #seen as /portal/redlion; keep as 2 separate paths so can detect other portals
    '/hudson', #Hudson CI
    '/stalker_portal', #IPTV middleware
    '/manager/text/list', #Tomcat
    '/manager/html', #Tomcat (Nmap fingerprint)
    '/Temporary_Listen_Addresses', #Windows Communication Framework
    '/webfig',
    '/solr',
    '/ckeditor',
    '/Telerik',
    '/showLogin.cc', #ManageEngine
    '/api/session/properties', #MetaBase
    '/sugar_version.json', #SugarCRM
    '/sitecore/', #Sitecore, seen as /sitecore/shell/sitecore.version.xml
    '/level/15/exec/-/sh/run/CR', #Cisco routers without authentication on the HTTP interface.
    '/+CSCOE+', '/CSCOE', #Cisco firewall WebVPN service
    '/Portal0000.htm', '__Additional', #Siemens S7–3**, PCS7 - scada servers - nmap scan
    '/docs/cplugError.html/', '/Portal/Portal.mwsl', #Siemens Simatic S7 scada devices - nmap scan
    '/CSS/Miniweb.css', #more scada servers
    '/localstart.asp', #old IIS vuln, nmap scan
    '/scripts/WPnBr.dll', #Citric XenApp and XenDesktop - Stack-Based Buffer Overflow in Citrix XML Service
    '/exactarget', #salesforce stuff
    '/cgi/networkDiag.cgi', # Sunhillo SureLine https://nvd.nist.gov/vuln/detail/CVE-2021-36380
    '/nation.php', #Seen posting form-encoded data to it: tuid=727737499&control=fconn&payload=d0xxZtY5RVygPWB%2B
    '/V5wZ', '/EIei', '/fw6I', #seen a few sets of requests that include each of these
    '/glass.php',
    'e3e7e71a0b28b5e96cc492e636722f73/4sVKAOvu3D/BDyot0NxyG.php', #Need to look this up
    '/is-bin', #Seen this a handful of times now, along with a cookie.
    '/telescope/requests',
    '/debug/default/view', #/debug/default/view?panel=config
    #'autodiscover/autodiscover.json?@zdi/Powershell', #Exchange RCE, see https://www.zerodayinitiative.com/blog/2022/11/14/control-your-types-or-get-pwned-remote-code-execution-in-exchange-powershell-backend
    'autodiscover/autodiscover', 'ews/autodiscover', #Exchange, see above
    '/vpnsvc/connect.cgi', #SoftEther probe, often by China GFW; see https://ensa.fi/active-probing/#probetype-softether
    '/.vscode/', # Seen probing for both /.vscode/.env and /.vscode/sftp.json
    'META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.properties',
    '/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application',
    '/v2/_catalog', #Docker container registry
    'readme.', #readme.txt, .md, etc
    '/ddnsmngr.cmd', #D-Link DSL-2640B Unauthenticated Remote DNS Change Exploit
    '/userRpm/WanDynamicIpCfgRpm.htm', #TP-LINK Model No. TL-WR340G/TL-WR340GD - Multiple Vulnerabilities - https://www.exploit-db.com/exploits/34583
    '/userRpm/LanDhcpServerRpm.htm', #see above
    '/dnscfg.cgi', #D-Link ADSL DSL-2640U Unauthenticated Remote DNS Change Exploit https://www.exploit-db.com/exploits/42195
    '/goform/setSysTools', #https://packetstormsecurity.com/files/162258/Multilaser-Router-RE018-AC1200-Cross-Site-Request-Forgery.html
    '/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile', #CVE-2019-1003000 Jenkins Script Security Plugin
]

def is_misc_software_probe(request):
    """ Misc software probes I see often. """
    path = request.path
    #Note: alphabetize these, it's getting too long. Could also import them from a txt file
    return any(target.lower() in path.lower() for target in MISC_SOFTWARE_PROBE_PATHS)

def is_wordpress_attack(request):
    path = request.path
    WORDPRESS_PATHS = [
        '/wordpress',
        '/wp/',
        '/wp-content',
        '/wp-admin',
        '/wp-login', #/wp-login.php
        '/wp-upload',
        '/wp-includes',
        '/wp-json',
        'xmlrpc.php',
        '/wp-blog',
    ]
    return any(target in path.lower() for target in WORDPRESS_PATHS)

def is_nmap_http_scan(request):
    """ Nmap HTTP scans. """
    if request.method == 'GET':
        path = request.path
        NMAP_HTTP_PATHS = [
            '/nmaplowercheck', #HTTP scan
            '/NmapUpperCheck', #HTTP scan
            '/Nmap/folder/check', #HTTP scan
            '/evox/about', #Trane Tracer SC - Industrial control panels
            '/HNAP1', #Some network gear
        ]
        return any(target.lower() in path.lower() for target in NMAP_HTTP_PATHS)
    return False

def is_nmap_vuln_probe(request):
    """ Some Nmap vulnerability probes. """
    if request.method == 'GET':
        path = request.path
        NMAP_VULN_PATHS = [
            '/../../../../../../../../../../etc/passwd',
            '/../../../../../../../../../../boot.ini',
            '/sdk/../../../../../../../etc/vmware/hostd/vmInventory.xml',
            '/sdk/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/etc/vmware/hostd/vmInventory.xml', #Path traversal in VMWare (CVE-2009-3733)
        ]
        return any(target in path for target in NMAP_VULN_PATHS)
    return False

# More specific bots/malware

def is_mirai_dvr(request) -> bool:
    """ Hisense Hi3520 dvr interface command injection vuln.
    POST to /dvr/cmd, user-agent usually 'Abcd'. Body is XML, including a command injection
    to download a Mirai/other loader with varying filename. Usually followed by another POST attempting
    to trigger a device restart. """
    EXPLOIT_PATH = '/dvr/cmd'
    if request.method == 'POST' and request.path.lower() == EXPLOIT_PATH:
        EXPLOIT_PATTERN = r'^.*<DVR Platform="Hi3520">.*<NTP Enable="True" Interval=.* Server=.*/>.*$'
        regex = re.compile(EXPLOIT_PATTERN, re.IGNORECASE)
        if regex.match(request.get_data(as_text=True)):
            return True
    return False

def is_mirai_netgear(request) -> bool:
    """ Attempts to exploit old Netgear DGN interface command injection vuln.
    Commonly exploited by Mirai/variants. """
    EXPLOIT_PATH = '/setup.cgi'
    if request.path.lower() == EXPLOIT_PATH:
        EXPLOIT_PATTERN = r'^(next_file=netgear.cfg&todo=syscmd&cmd=.*&curpath=.*&)?currentsetting.htm=.*$'
        regex = re.compile(EXPLOIT_PATTERN, re.IGNORECASE)
        # Check query string against pattern
        if request.query_string:
            query_string_decoded = request.query_string.decode('utf-8', errors = 'replace')
            return regex.match(query_string_decoded)
    return False

def is_mirai_jaws(request) -> bool:
    """ JAWS Webserver unauthenticated shell command execution in MVPower/other DVRs.
    Commonly exploited by Mirai.
    https://www.exploit-db.com/exploits/41471/ """
    EXPLOIT_PATH = '/shell'
    if request.path.lower() == EXPLOIT_PATH:
        if request.query_string:
            return True
    return False

def is_mirai_ua(request) -> bool:
    """ Hello, world = UA commonly used in requests from Mirai botnet hosts. """
    user_agent = request.headers.get('User-Agent', '')
    MIRAI_USER_AGENT = 'Hello, world'
    return user_agent == MIRAI_USER_AGENT

def is_androx(request) -> bool:
    """ AndroxGh0st malware, sends a POST after searching for leaked app secrets in exposed Laravel/other .env.
    Method is POST; content-type is set as form data. Path varies.
    Almost always preceded by a request like `GET /.env`, which will probably get reported before this POST request does.
    Return True if 0x[] or 0x01[] etc found in form data keys. """

    '''ANDROX_SIGS = [
        # Just a few examples I've seen. Leaving this here for reference.
        #'androxgh0st', 'legion', 'ridho', 'janc0xsec', 'CREX', '0x0day' #some values I've seen so far
        # Keys:
        '0x[]',
        '0x01[]',
    ]'''

    if request.method == 'POST' and request.content_type == 'application/x-www-form-urlencoded':
        form_data_keys = [item for item in request.form.keys()]
        # Match for "0x" followed by 0-8 (arbitrary, could be more but I've only seen up to ~5) of any char, then brackets "[]". Example "0x[]" or "0x01[]"
        ANDROX_SIG_REGEX = r'^0x.{0,16}\[\]$'
        regex = re.compile(ANDROX_SIG_REGEX, re.IGNORECASE)
        return any(regex.search(_) for _ in form_data_keys)
    return False

def is_cobalt_strike_scan(request):
    """ Cobalt Strike scan, either from the software itself or researchers. """
    if request.method == 'GET':
        path = request.path
        COBALT_STRIKE_BEACONS = [
            'aaa9', # 32-bit beacon
            'aab8', # 32-bit beacon
            'aab9', # 64-bit
            'aac8', # 64-bit
        ]
        return any(target in path.lower() for target in COBALT_STRIKE_BEACONS)
    return False

def is_systembc_path(request):
    """ systembc malware paths I see requested. """
    path = request.path
    SYSTEMBC_PATHS = [
        '/systembc', #This will match 1st, but adding others for reference.
        '/systembc/geoip',
        '/systembc/geoip/geoip2.phar',
        '/systembc/geoip/GeoLite2-City.mmdb',
        '/systembc/index.html',
        '/systembc/password.php', #Almost all are this one.
    ]
    return any(target.lower() in path.lower() for target in SYSTEMBC_PATHS)

def is_wsus_attack(request):
    """ Requests attempting to proxy a request for a Windows Update .cab file,
    with Windows-Update-Agent UA. Some kind of WSUS attack I think. 
    The URL in each one is http://docs.microsoft.com/c/msdownload/update/software/update/2021/11/6632de33-967441-x86.cab 
    and UA = Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.31 """
    user_agent = request.headers.get('User-Agent', '')
    WSUS_ATTACK_UA = 'Windows-Update-Agent'
    return True if WSUS_ATTACK_UA in user_agent else False

def is_rocketmq_probe(request):
    """ Probing for CVE-2023-33246 RocketMQ Remote Code Execution Exploit """
    path = request.path
    ROCKETMQ_PROBE_PATH = '/cluster/list.query'
    return ROCKETMQ_PROBE_PATH in path.lower()

def is_datadog_trace(request):
    """ Spamming Datadog trace headers. """
    DATADOG_HEADERS = [
        'X-Datadog-Trace-Id',
        'X-Datadog-Parent-Id',
        'X-Datadog-Sampling-Priority',
    ]
    for datadog_header in DATADOG_HEADERS:
        if request.headers.get(datadog_header):
            return True
    return False

def is_tpl_exploit(request):
    """ CVE-2023-1389 TP-Link AX21 router exploit.
    Usually seen downloading a Mirai loader 'tenda.sh' - probably applies to some Tenda gear as well. """
    TPL_EXP_PATH = '/cgi-bin/luci/;stok=/locale'
    TPL_EXP_PATTERN = r'^form=country&operation=write&country=.'
    regex = re.compile(TPL_EXP_PATTERN, re.IGNORECASE)
    if (
        request.path == TPL_EXP_PATH
        #or request.query_string.decode().startswith('form=country&operation=write&country=')
        or regex.search(request.query_string.decode(errors='replace'))
    ):
        return True
    return False

def is_zyxel_rci(request):
    """ CVE-2022-30525 Zyxel Firewall Unauthenticated Remote Command Injection """
    ZYXEL_PATH = '/ztp/cgi-bin/handler'
    if request.method != 'POST':
        return False
    else:
        return ZYXEL_PATH.lower() in request.path.lower()

def is_dlink_backdoor(request):
    """ CVE-2024-3272/CVE-2024-3273 Command Injection and Backdoor Account in D-Link NAS Devices """
    EXPLOIT_PATH = '/cgi-bin/nas_sharing.cgi'
    return request.path == EXPLOIT_PATH

def is_tbk_auth_bypass(request):
    """ CVE-2018-9995 TBK DVR4104/DVR4216 - Authentication bypass """
    EXPLOIT_PATH = '/device.rsp'
    EXPLOIT_PATTERN = r'^opt=.*&cmd=.*$'
    regex = re.compile(EXPLOIT_PATTERN, re.IGNORECASE)
    if (
        request.path == EXPLOIT_PATH
        and regex.search(request.query_string.decode(errors='replace'))
        and request.cookies.get('uid', 'None') == 'admin'
    ):
        return True
    else:
        return False

def is_hikvision_injection(request):
    ''' CVE-2021-36260 Hikvision unauthenticated command injection. '''
    # References: https://packetstorm.news/files/id/166167 https://www.cve.org/CVERecord?id=CVE-2021-36260
    EXPLOIT_PATH = '/SDK/webLanguage'
    # Return early if path doesn't match, to save CPU cycles.
    if request.path.lower() == EXPLOIT_PATH.lower():
        EXPLOIT_BODY_REGEX = r'^<\?xml version=.*encoding=.*>.*\s*.*<language>.*</language>.*$'
        regex = re.compile(EXPLOIT_BODY_REGEX, re.IGNORECASE)
        req_body_decoded = request.get_data().decode(errors='replace')
        # Now check method and body
        if (
            request.method == 'PUT'
            and regex.match(req_body_decoded)
        ):
            return True
    else:
        return False

def is_joomla_injection(request) -> bool:
    """ CVE-2023-23752 - Joomla injection. """
    EXPLOIT_PATH = '/api/index.php/v1/config/application'
    if request.path.lower() == EXPLOIT_PATH.lower():
        # Make pattern mostly optional, so probes for the path alone will match as well.
        EXPLOIT_PATTERN = r'^(public=true(&page%5Boffset%5D=.*&page%5Blimit%5D=.*)?)?$'
        regex = re.compile(EXPLOIT_PATTERN, re.IGNORECASE)
        # Really only need to check path, but might as well check query too.
        if regex.search(request.query_string.decode(errors='replace')):
            return True
    else:
        return False

# more generic rules

def is_post_request(request):
    """ Return True if POST. Any POST requests we receive are suspicious to begin with. """
    return request.method == 'POST'

def no_host_header(request):
    """ True if request contains no 'Host' header. Not *necessarily* malicious, but suspicious. """
    host_header = request.headers.get('Host')
    return host_header is None

def is_misc_get_probe(request):
    """ Any GET request that includes 1 or more query args. 
    Don't include POST requests; they'll already be reported by is_post_request(). """
    MISC_PROBE_METHODS = ['GET', 'HEAD']
    if request.method in MISC_PROBE_METHODS and request.args:
        return True
    return False

def is_programmatic_ua(request):
    """ Default user agents of programming language modules + http clients, i.e. Python requests, etc.
    Include curl/wget etc, but don't include specific bot UAs, those will go into another rule."""
    #TO-DO: Refactor this rule using regex.
    user_agent = request.headers.get('User-Agent', '')
    # Most of the UA's include a version #, i.e. Wget/1.21.3, we'll just search for the name
    PROGRAMMATIC_USER_AGENTS = [
        'aiohttp/', #i.e. Python/3.10 aiohttp/3.9.0
        'curl/',
        'Custom-AsyncHttpClient',
        'fasthttp',
        'Go-http-client',
        'Hello World', #Not to be confused with Mirai botnet's 'Hello, world' ua with comma
        'Java/', #i.e. Java/1.8.0_362
        'libwww-perl',
        'masscan/', #https://github.com/robertdavidgraham/masscan
        'Mozila/5.0', #Note misspelling; all with this UA have been command injection of some sort
        'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)',
        'Odin; https://docs.getodin.com/', #Odin
        'Offline Explorer/', #WWW Offline Explorer
        'python-httpx/',
        'python-requests/',
        'python-urllib3/',
        'Wget/',
        'WinHttp.WinHttpRequest',
        'xfa1',
        'zgrab/',
    ]
    return any(target in user_agent for target in PROGRAMMATIC_USER_AGENTS)

def is_xmlhttprequest(request):
    """ True if request contains X-Requested-With header set to XMLHttpRequest. """
    _x_requested_with = request.headers.get('X-Requested-With')
    if _x_requested_with:
        return 'XMLHttpRequest' in _x_requested_with

def is_proxy_attempt(request):
    """ True if request contains a Proxy-Connection or Proxy-Authorization header. """
    PROXY_HEADERS = [
        'Proxy-Connection',
        'Proxy-Authorization',
    ]
    for proxy_header in PROXY_HEADERS:
        if proxy_header in request.headers:
            return True
    return False

def is_dns_probe(request):
    """ True if content-type = application/dns-message, query string contains 'dns=',
    or path matches any of DNS_PROBE_PATHS. """
    # Can be either a GET with query params, or POST with the queried domain as the body,
    # occasionally neither. Content-type in all of them has been application/dns-message.
    # Scheme obv will be HTTPS, so check that first.
    DNS_CONTENT_TYPE = 'application/dns-message'
    DNS_PROBE_PATHS = [
        '/dns-query',
        '/resolve',
        '/query',
    ]
    DNS_QUERY_ARG = 'dns'
    #If scheme is HTTPS, check for any of the indicators and return True if found.
    if request.scheme == 'https':
        if (
            DNS_CONTENT_TYPE in request.headers.get('Content-type', '')
            or DNS_QUERY_ARG in request.args.keys()
            or any(target == request.path.lower() for target in DNS_PROBE_PATHS)
        ):
            return True
    return False

def host_is_ip_v4(request) -> bool:
    """ Return true if request.host is an IPv4 address. """
    #rhost = request.host
    #rhost = rhost.split(":", 1)[0] #Remove port if present
    # Use urlparse instead:
    rhost = urlparse(request.base_url)
    rhost = rhost.hostname
    try:
        val = ipaddress.IPv4Address(rhost)
        return True
    except ipaddress.AddressValueError:
        return False

def host_is_ip_v6(request) -> bool:
    """ Return true if request.host is an IPv6 address. """
    rhost = urlparse(request.base_url)
    rhost = rhost.hostname
    # Validate as an IPv6 addr, via ipaddress module
    try:
        val = ipaddress.IPv6Address(rhost)
        return True
    except ipaddress.AddressValueError:
        return False

# Some misc rules to help prevent false positives.
# Don't be that oblivious admin who reports NTP servers etc.

def is_research(request):
    """ Reduce score if it's known benign research orgs/scanners, don't need to report them.
    Can be easily spoofed though, so don't just zero it. Most just request /, but some trigger
    other rules while checking for vulnerabilities.
    TODO: Check for hostnames as well- import from a text file. """
    user_agent = request.headers.get('User-Agent')
    RESEARCH_USER_AGENTS = [
        'CensysInspect', #Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)
        'Expanse, a Palo Alto Networks company',
        'https://developers.cloudflare.com/security-center/', #CF Security Center
        'Cloudflare-SSLDetector',
        'HTTP Banner Detection (https://security.ipip.net)', # *.security.ipip.net
        'http://tchelebi.io', #Black Kite / http://tchelebi.io
        '+https://internet-measurement.com/',
        'https://gdnplus.com:Gather Analyze Provide.',
        '+http://www.bing.com/bingbot.htm', #Saw bingbot crawling it, might as well add it.
        'abuse.xmco.fr',
        'SecurityScanner',
        'infrawatch/', #infrawat.ch
        'Uptime-Kuma/', #Uptime-Kuma/1.23.1 - Uptime Kuma's default ua
        'Security Headers Synthetic Checker', #Security headers checker
        '+http://www.google.com/bot.html', #google bot
        '(compatible; GoogleOther)', #Google, another
        'keycdn-tools/br', #KeyCDN brotli checker
        'keycdn-tools/curl', #KeyCDN HTTP Header Checker
        'keycdn-tools/perf', #KeyCDN Performance Test
        'Mozilla/5.0 (compatible; GenomeCrawlerd/1.0; +https://www.nokia.com/networks/ip-networks/deepfield/genome/)', #Nokia Deepfield Genome
        'Mozilla/5.0 (compatible; NetcraftSurveyAgent/1.0; +info@netcraft.com)', #Netcraft
        '(compatible; Netcraft Web Server Survey)',#Mozilla/4.0 (compatible; Netcraft Web Server Survey)
        'Cloud mapping experiment. Contact research@pdrlabs.net',
        '(+http://code.google.com/appengine; appid: s~virustotalcloud)', #VirusTotal URL check
        '(scanner.ducks.party)',#Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 (scanner.ducks.party)
        '+https://leakix.net)',#Mozilla/5.0 (l9scan/2.0.734313e20373e21323e2430313; +https://leakix.net)
        '+http://archive.org/details/archive.org_bot', #archive.org bot, ex: Mozilla/5.0 (compatible; archive.org_bot +http://archive.org/details/archive.org_bot) Zeno/501a4cd warc/v0.8.57
    ]
    if user_agent is None:
        return False
    #return any(target in user_agent for target in RESEARCH_USER_AGENTS)
    for research_user_agent in RESEARCH_USER_AGENTS:
        if research_user_agent in user_agent:
            return True
    return False

# CUSTOM RULES

def matches_custom_rule(request):
    """ Custom string search. Read custom rule from config if found, then check for the sigs in the 
    path+query, POSTed data, or header values. """
    if current_app.config.get('CUSTOM_SIGNATURES'):
        # Read the list from config
        CUSTOM_SIGNATURES = current_app.config.get('CUSTOM_SIGNATURES')
        # Validate it's a list
        if not isinstance(CUSTOM_SIGNATURES, list):
            logging.warning('Warning: CUSTOM_SIGNATURES is not a valid list; skipping rule.')
            return False

        __request_url = request.url
        __request_body = request.get_data(as_text=True)
        __header_values_joined = ''.join(request.headers.values())

        # Check for signatures in the path+query, POSTed data, and headers
        if (
            any(target.lower() in __request_url.lower() for target in CUSTOM_SIGNATURES)
            or any(target.lower() in __request_body.lower() for target in CUSTOM_SIGNATURES)
            or any(target.lower() in __header_values_joined.lower() for target in CUSTOM_SIGNATURES)
        ):
            return True
        else:
            return False
    else:
        #logging.debug('No CUSTOM_SIGNATURES found.')
        return False

def matches_custom_regex(request):
    """ Custom regex, read patterns from config. """
    if current_app.config.get('CUSTOM_REGEX'):
        # Read the list of patterns from config
        CUSTOM_REGEX = current_app.config.get('CUSTOM_REGEX')
        # Validate it's a list; return early if not.
        if not isinstance(CUSTOM_REGEX, list):
            logging.warning('Warning: CUSTOM_REGEX is not a valid list; skipping rule.')
            return False
        # Join patterns with pipe (regex alternate). Ignore case (i flag)
        custom_regex_pattern = '|'.join(CUSTOM_REGEX)
        regex = re.compile(custom_regex_pattern, re.IGNORECASE)

        # Check the full URL (incl. any query args)
        if regex.search(request.url):
            return True
        # Check the body
        _body = request.get_data(as_text=True)
        if regex.search(_body):
            return True
        # Check header values
        __header_values_joined = ''.join(request.headers.values())
        if regex.search(__header_values_joined):
            return True
        # If no signatures found in either, return False
        return False
    else:
        return False

# END RULES
# BEGIN RULE CHECKING FUNCTIONS

def append_to_report(comment, category_codes, report_categories, report_comment):
    """ Append the rule name and category to the report params. """
    for category in category_codes:
        # Avoid duplicate categories
        if category not in report_categories:
            report_categories.add(category)
    report_comment += comment
    return report_comment

def check_all_rules():
    """ Will call this function from the main route; Check request object against all
    detection rules, and submit report to AbuseIPDB.
    Usage: reported = check_all_rules() #returns reported = 0/1. """

    # Initialize categories+comment empty, then append_to_report() will fill in if any rules match.
    report_categories = set()
    # Check whether request contains query args; if so, include it in report comment.
    if request.query_string is not None and len(request.query_string.decode()) > 2:
        report_comment = f'Detected malicious request: {request.method} {request.full_path} \nDetections triggered: '
    else:
        report_comment = f'Detected malicious request: {request.method} {request.path} \nDetections triggered: '
    rules_matched = 0 #This will be our "score"; if score > 0, then report it.

    # Define rules as a list of tuples, where each tuple contains:
    # (rule function, rule name/comment, category code)
    # AbuseIPDB categories: https://www.abuseipdb.com/categories
    rules = [
        (is_env_probe, 'Environment/config probe', ['21']),
        (is_php_easter_egg, 'PHP easter eggs', ['21']),
        (is_phpmyadmin_probe, 'PhpMyAdmin probe', ['21']),
        (is_cgi_probe, 'CGI probe/attack', ['21']),
        (is_injection_attack, 'Command injection', ['21']),
        (is_path_traversal, 'Path traversal', ['21']),
        (is_misc_software_probe, 'Misc software probe/exploit', ['21']),
        (is_wordpress_attack, 'Wordpress attack', ['21']),
        (is_nmap_http_scan, 'Nmap HTTP scan', ['21']),
        (is_nmap_vuln_probe, 'Nmap probe', ['21']),
        (is_mirai_dvr, 'HiSense DVR exploit', ['23','21']),
        (is_mirai_netgear, 'Netgear DGN command injection exploit', ['23','21']),
        (is_mirai_jaws, 'MVPower Jaws webserver command injection', ['23', '21']),
        (is_mirai_ua, 'User-agent associated with Mirai', ['23','19']),
        (is_androx, 'AndroxGh0st/variant', ['21']),
        (is_cobalt_strike_scan, 'Cobalt Strike path', ['21']),
        (is_systembc_path, 'SystemBC malware path', ['21']),
        (is_wsus_attack, 'Windows WSUS attack', ['21']),
        (is_rocketmq_probe, 'RocketMQ probe CVE-2023-33246', ['21']),
        (is_datadog_trace, 'Unauthorized probe/scan', ['21']),
        (is_tpl_exploit, 'TP-Link CVE-2023-1389', ['15','21','23']),
        (is_zyxel_rci, 'Zyxel CVE-2022-30525', ['15','21','23']),
        (is_dlink_backdoor, 'D-Link CVE-2024-3272/CVE-2024-3273', ['15','21','23']),
        (is_tbk_auth_bypass, 'CVE-2018-9995 TBK DVR auth bypass', ['21','23']),
        (is_hikvision_injection, 'CVE-2021-36260 Hikvision IP camera command injection', ['21', '23']),
        (is_joomla_injection, 'Joomla CVE-2023-23752', ['21','16']),
        (is_post_request, 'Suspicious POST request', ['21']),
        (no_host_header, 'No Host header', ['21']),
        (is_misc_get_probe, 'GET with unexpected args', ['21']),
        (is_programmatic_ua, 'Automated user-agent', ['21']),
        (is_xmlhttprequest, 'Automated user-agent', ['21']),
        (is_proxy_attempt, 'Sent proxy headers', ['21']),
        (is_dns_probe, 'Probe DNS-over-HTTPS', ['2','14']),
        (host_is_ip_v4, 'Access via IP addr (v4)', ['21']),
        (host_is_ip_v6, 'Access via IP addr (v6)', ['21']),
        (matches_custom_rule, 'Custom rule', ['21']),
        (matches_custom_regex, 'Custom regex', ['21']),
    ]

    # Now check against each detection rule, and if positive(True), then append to the report.
    for detection_rule, log_message, category_code in rules:
        if detection_rule(request): #If rule returns true/truthy, i.e. rule matched
            report_comment = append_to_report(
                f'{log_message}\n',
                category_code,
                report_categories,
                report_comment
            )
            logging.debug(f'Rule matched: {log_message}')
            rules_matched += 1

    # Lower the score for known benign researchers/scanners
    if is_research(request):
        if rules_matched > 0:
            rules_matched -= 2

    # If any rules matched, report to AbuseIPDB.
    if rules_matched > 0:
        # Check whether an API key is configured first.
        if current_app.config.get('ABUSEIPDB'):
            if exempt_from_reporting(get_real_ip()):
                # If the IP is in the exempt subnets list, don't submit report.
                reported = 0
                logging.info(f'Address exempt from reporting: {get_real_ip()}')
                return reported
            else:
                try:
                    # Check now whether IP has already been reported
                    if not already_reported(get_real_ip()):
                        reported = submit_report(report_comment, report_categories)
                        logging.info(f'Matched {rules_matched} rules. Reported to AbuseIPDB.')
                    else:
                        reported = 0
                except requests.exceptions.ConnectionError as e:
                    reported = 0
                    logging.error(f'Connection error while submitting report: {str(e)}')
        # If no API key configured, skip reporting and just return 0
        else:
            reported = 0
            logging.info(f'Matched {rules_matched} rules. No AbuseIPDB key found, not reported.')
        return reported
    else:
        reported = 0
        logging.debug('Request matched no report rules.')
        return reported
