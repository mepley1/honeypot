""" Functions related to auto-reporting. """

import datetime
import ipaddress
import json
import logging
import requests
import re
from flask import request, current_app

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
    """ Check whether the IP is within any of configured exempt subnets. """
    if not current_app.config.get('EXEMPT_SUBNETS'):
        return False #If no subnets configured, then not exempt.
    EXEMPT_SUBNETS = current_app.config.get('EXEMPT_SUBNETS')
    _ip_addr = ipaddress.ip_address(_ip)
    '''for subnet in EXEMPT_SUBNETS:
        try:
            if ip in ipaddress.ip_network(subnet):
                return True
        except ValueError:
            # Invalid subnet format, skip to the next one
            continue
    return False'''

    return any(_ip_addr in ipaddress.ip_network(exempt_subnet) for exempt_subnet in EXEMPT_SUBNETS)

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

def is_env_probe(request):
    """ Returns True if path contains any of target strings. Only catch GET for this rule.
    Some environment/config probes I see often. """
    path = request.path
    method = request.method
    ENV_PROBE_METHODS = ['GET', 'HEAD']
    ENV_PROBE_PATHS = [
        '.env', #The big winner
        '.htaccess', '.htpasswd',
        'config', '/conf', '.conf',
        '/admin',
        '.git', '.svn', #version control
        '/.aws',
        'backend',
        'phpinfo',
        '/eval',
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
        '/auth',
        '/login',
        '/logon',
        '/database',
        '/scripts',
        '/99vt', '/99vu', '/gate.php', '/aaaaaaaaaaaaaaaaaaaaaaaaaqr', #some misc malware
        '/form.html', 'upl.php', 'info.php', '/bundle.js', '/files/', #Usually probed together
        '/whyareugay', # Some malware maybe? Been seeing it from the same couple subnets
        '/log/',
        '/jquery.js',
        '/jquery-3.3.1.min.js', #seen this a bunch of times now
        '.json',
    ]
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
    #posted_data_decoded = request.data.decode(errors='replace')
    posted_data_decoded = request.get_data(as_text=True)
    header_values_joined = ''.join(request.headers.values())
    INJECTION_SIGNATURES = [
        ';sh',
        '|sh',
        '.sh;',
        'sh+',
        '/tmp;',
        '+/tmp',
        'file=', # might need to adjust this one, could be a real query
        ';wget',
        'wget+',
        '&wget',
        ';chmod',
        'cd+',
        ';rm -rf', #formatted with spaces in headers injection
        'rm+-rf',
        ' && ',
        '<?php', 'shell_exec', 'base64_decode', #php injection
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

def is_misc_software_probe(request):
    """ Misc software probes I see often. """
    path = request.path
    #Note: alphabetize these, it's getting too long. Could also import them from a txt file
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
        'autodiscover/autodiscover.json?@zdi/Powershell', #Exchange RCE, see https://www.zerodayinitiative.com/blog/2022/11/14/control-your-types-or-get-pwned-remote-code-execution-in-exchange-powershell-backend
    ]
    return any(target.lower() in path.lower() for target in MISC_SOFTWARE_PROBE_PATHS)

def is_wordpress_attack(request):
    path = request.path
    WORDPRESS_PATHS = [
        '/wordpress',
        '/wp-content',
        '/wp-admin',
        '/wp-login', #/wp-login.php
        '/wp-upload',
        '/wp-includes',
        'xmlrpc.php',
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

def is_mirai_dvr(request):
    """ Mirai botnet looking for Hi3520 dvr interfaces to exploit.
    Usually a POST to /dvr/cmd with user-agent Abcd, posting XML including a wget command injection
    to download a Mirai loader with varying filename, followed by another POST attempting to
    trigger a device restart. """
    path = request.path
    MIRAI_DVR_PATH = '/dvr/cmd'
    if request.method == 'POST' and path.lower() == MIRAI_DVR_PATH:
        posted_data = request.get_data(as_text=True)
        MIRAI_DVR_PAYLOADS = [
            '<DVR Platform="Hi3520">',
            '<SetConfiguration File="service.xml">',
            '&wget',
            '|sh',
            'NTP Enable=',
            'http://',
        ]
        # If path==/dvr/cmd and any of the payload strings are there, it's definitely an attempt,
        # though not necessarily always Mirai- would have to check the file it downloads, but each one
        # that I've seen has been a Mirai loader.
        return any(target in posted_data for target in MIRAI_DVR_PAYLOADS)
    return False
 
def is_mirai_netgear(request):
    """ Mirai attempting to exploit old Netgear DGN interface command injection vuln. """
    path = request.path
    MIRAI_NETGEAR_PATH = '/setup.cgi'
    MIRAI_NETGEAR_SIGNATURES = [
        'next_file=netgear.cfg',
        'todo=syscmd',
        'cmd=',
        ';wget',
        '/tmp/netgear',
        'curpath=/&currentsetting.htm=1',
    ]
    # Exit early if path doesn't match, for performance.
    if path.lower() != MIRAI_NETGEAR_PATH:
        return False
    # Check query params for the mirai signatures
    if request.query_string is not None:
        query_string_decoded = request.query_string.decode('utf-8', errors = 'replace')
        return any(target in query_string_decoded for target in MIRAI_NETGEAR_SIGNATURES)
    return False

def is_mirai_jaws(request):
    """ JAWS Webserver unauthenticated shell command execution.
    https://www.exploit-db.com/exploits/41471/ """
    path = request.path
    MIRAI_JAWS_PATH = '/shell'
    MIRAI_JAWS_SIGNATURES = [
        '/tmp;rm',
        ';wget',
        '/jaws;sh',
        '/tmp/jaws',
    ]
    if path.lower() != MIRAI_JAWS_PATH:
        return False
    if request.query_string is not None:
        query_string_decoded = request.query_string.decode()
        return any(target in query_string_decoded for target in MIRAI_JAWS_SIGNATURES)
    return False

def is_mirai_ua(request):
    """ Hello, world = UA commonly used in requests sent by Mirai botnet nodes. 
    Not a guarantee that it's Mirai, but I haven't seen it anywhere else. """
    user_agent = request.headers.get('User-Agent', '')
    MIRAI_USER_AGENT = [
        'Hello, world',
    ]
    return user_agent == MIRAI_USER_AGENT

def is_androx(request):
    """ AndroxGh0st malware, searching for leaked app secrets in exposed Laravel .env.
    Method usually POST as form data. Path varies. """
    if request.method == 'POST' and request.content_type == 'application/x-www-form-urlencoded':
        form_data = ''.join(request.form.values())
        return 'androxgh0st' in form_data #True if both conditions met, else False
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
        '/systembc',
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


# more generic rules

def is_post_request(request):
    """ Return True if POST. Any POST requests we receive are suspicious to begin with. """
    return request.method == 'POST'

def no_host_header(request):
    """ True if request contains no 'Host' header. """
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
    user_agent = request.headers.get('User-Agent', '')
    # Most of the UA's include a version #, i.e. Wget/1.21.3, we'll just search for the name
    PROGRAMMATIC_USER_AGENTS = [
        'aiohttp/',
        'curl/',
        'fasthttp',
        'Go-http-client',
        'Hello World', #Not to be confused with Mirai botnet's 'Hello, world' ua with comma
        'libwww-perl',
        'masscan/', #https://github.com/robertdavidgraham/masscan
        'Mozila/5.0', #Note misspelling; all with this UA have been command injection of some sort
        'Odin; https://docs.getodin.com/', #Odin
        'Offline Explorer/', #WWW Offline Explorer
        'python-httpx/',
        'python-requests/',
        'Wget/',
        'WinHttp.WinHttpRequest',
        'xfa1',
        'zgrab/',
    ]
    return any(target in user_agent for target in PROGRAMMATIC_USER_AGENTS)

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
    """ True if path contains '/dns-query' """
    DNS_PROBE_PATH = '/dns-query'
    return DNS_PROBE_PATH in request.path.lower()

# Some misc rules to help prevent false positives.
# Don't be that oblivious admin who reports NTP servers etc.

def is_research(request):
    """ Reduce score if it's known benign research orgs/scanners, don't need to report them.
    Can be easily spoofed though, so don't just zero it. Most just request /, but some trigger
    other rules while checking for vulnerabilities. """
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
        'Security Headers Synthetic Checker', # Security headers checker
    ]
    if user_agent is None:
        return False
    #return any(target in user_agent for target in RESEARCH_USER_AGENTS)
    for research_user_agent in RESEARCH_USER_AGENTS:
        if research_user_agent in user_agent:
            return True
    return False

def matches_custom_rule(request):
    """ Read custom rule from config if found, then check for the sigs in the 
    path+query, POSTed data, or header values. """
    if current_app.config.get('CUSTOM_SIGNATURES'):
        _req_url = request.url
        _req_body = request.get_data(as_text=True)
        _header_values_joined = ''.join(request.headers.values())
        # Read the list from config
        CUSTOM_SIGNATURES = current_app.config.get('CUSTOM_SIGNATURES')
        # Check for signatures in the path+query, POSTed data, and headers
        if (
            any(target in _req_url.lower() for target in CUSTOM_SIGNATURES)
            or any(target in _req_body.lower() for target in CUSTOM_SIGNATURES)
            or any(target in _header_values_joined.lower() for target in CUSTOM_SIGNATURES)
        ):
            return True
        else:
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
    # Check whether request contains query args; if so, include it.
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
        (is_misc_software_probe, 'Misc software probe', ['21']),
        (is_wordpress_attack, 'Wordpress attack', ['21']),
        (is_nmap_http_scan, 'Nmap HTTP scan', ['21']),
        (is_nmap_vuln_probe, 'Nmap probe', ['21']),
        (is_mirai_dvr, 'HiSense DVR exploit, likely Mirai', ['23','21']),
        (is_mirai_netgear, 'Netgear command injection exploit, likely Mirai', ['23','21']),
        (is_mirai_jaws, 'Jaws webserver command injection, likely Mirai', ['23', '21']),
        (is_mirai_ua, 'User-agent associated with Mirai', ['23','19']),
        (is_androx, 'Detected AndroxGh0st', ['21']),
        (is_cobalt_strike_scan, 'Cobalt Strike path', ['21']),
        (is_systembc_path, 'SystemBC malware path', ['21']),
        (is_wsus_attack, 'Windows WSUS attack', ['21']),
        (is_rocketmq_probe, 'RocketMQ probe CVE-2023-33246', ['21']),
        (is_datadog_trace, 'Unauthorized probe/scan', ['21']),
        (is_post_request, 'Suspicious POST request', ['21']),
        (no_host_header, 'No Host header', ['21']),
        (is_misc_get_probe, 'GET with unexpected args', ['21']),
        (is_programmatic_ua, 'Automated user-agent', ['21']),
        (is_proxy_attempt, 'Sent proxy headers', ['21']),
        (is_dns_probe, 'Probe DNS-over-HTTPS', ['2','14'])
    ]

    # Now check against each detection rule, and if positive(True), then append to the report.
    for detection_rule, log_message, category_code in rules:
        if detection_rule(request):
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
            rules_matched -= 1

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
                    reported = submit_report(report_comment, report_categories)
                    logging.info(f'Matched {rules_matched} rules. Reported to AbuseIPDB.')
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
