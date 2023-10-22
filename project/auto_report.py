""" Functions related to auto-reporting. """

import datetime
import json
import logging
import requests
from flask import request, current_app

def get_real_ip():
    """ Get client's IP from behind Nginx. """
    if 'X-Real-Ip' in request.headers:
        real_ip = request.headers.get('X-Real-Ip')
    else:
        real_ip = request.remote_addr
    return real_ip

def submit_report(report_comment, report_categories):
    """ Submit the report. Usage: reported = submit_report(report_comment, report_categories) """
    api_url = 'https://api.abuseipdb.com/api/v2/report'
    params = {
            'ip': get_real_ip(),
            'categories': report_categories,
            'comment': report_comment,
            'timestamp': datetime.datetime.now().astimezone().replace(microsecond=0).isoformat(), #https://stackoverflow.com/questions/2150739/iso-time-iso-8601-in-python
    }
    headers = {
            'Accept': 'application/json',
            'Key': current_app.config["ABUSEIPDB"],
    }
    response = requests.post(url = api_url, headers = headers, params = params)
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

def is_env_probing(request):
    """ Returns True if path contains any of target strings. """
    path = request.path
    env_probe_paths = ['.env', 'config', 'admin', '.git', 'backend', 'phpinfo', '/eval', 'echo.php']
    return any(target in path for target in env_probe_paths)

def is_phpmyadmin_probe(request):
    """ Probing for PHPMyAdmin instances. """
    path = request.path
    pma_probe_paths = ['phpmyadmin', '/mysql/', '/sqladmin/', '/mysqlmanager/', '/myadmin/']
    return any(target in path for target in pma_probe_paths)

def is_mirai_dvr(request):
    """ Mirai botnet looking for Hi3520 dvr interfaces to exploit.
    Usually a POST to /dvr/cmd with user-agent Abcd, posting XML including a wget command injection
    to download a Mirai loader with varying filename, followed by another POST attempting to
    trigger a device restart. """
    path = request.path
    body = request.data
    user_agent = request.headers.get('User-Agent')

    mirai_dvr_path = '/dvr/cmd'
    mirai_dvr_payloads = ['<DVR Platform="Hi3520">', '<SetConfiguration File="service.xml">', 
        '&wget', '|sh', 'NTP Enable=', 'http://']

    # If path==/dvr/cmd and any of the payload strings are there, it's definitely an attempt,
    # though not necessarily always Mirai- would have to check the file it downloads, but each one
    # that I've seen has been a Mirai loader.
    if path == mirai_dvr_path:
        return any(target in body for target in mirai_dvr_payloads)

# more generic rules

def is_post_request(request):
    """ Return True if POST. Any POST requests we receive are suspicious to begin with. """
    return request.method == 'POST'

def no_host_header(request):
    """ True if request contains no HOST header. """
    host_header = request.headers.get('Host')
    return host_header is None

# some misc rules to help prevent false positives

def is_research(request):
    """ We can reduce score if it's known research orgs/scanners, don't really need to report. """
    user_agent = request.headers.get('User-Agent')
    research_user_agents = [
        'CensysInspect',
        'Expanse, a Palo Alto Networks company',
    ]
    if user_agent is None:
        return False
    #return any(target in user_agent for target in research_user_agents)
    for research_user_agent in research_user_agents:
        if research_user_agent in user_agent:
            return True
    return False

# END RULES

def append_to_report(comment, category, report_categories, report_comment):
    """ Append a note and category to the report params. """
    if category not in report_categories:
        report_categories.add(category)
    report_comment += comment
    return report_comment

def check_all_rules():
    """ This is the command we'll call from the main route; returns reported 0/1.
    Usage: reported = check_all_rules() """

    # Initialize these empty, then append_to_report() will fill them in if any rules match.
    report_categories = set()
    report_comment = "Honeypot detected attack:\n"

    rules_matched = 0 #This will be our "score"; if score > 0, then report it.

    # Check against our rules. There's probably a better way to do this.
    if is_env_probing(request):
        report_comment = append_to_report(f'Environment/config probe: {request.method} {request.path}\n',
            '21',
            report_categories,
            report_comment)
        rules_matched += 1
        logging.debug('Rule matched: Environment probe')

    if is_phpmyadmin_probe(request):
        append_to_report(f'PhpMyAdmin probe: {request.method} {request.path}\n',
            '21',
            report_categories,
            report_comment)
        rules_matched += 1
        logging.debug('Rule matched: PhpMyAdmin probing')

    if is_mirai_dvr(request):
        append_to_report(f'HiSense DVR exploit: {request.method} {request.path}\n'
            '23',
            report_categories,
            report_comment)
        logging.debug('Rule matched: HiSense DVR exploit')
        rules_matched += 1

    if is_post_request(request):
        report_comment = append_to_report(f'Suspicious POST request: {request.method} {request.path}\n',
            '21',
            report_categories,
            report_comment)
        logging.debug('Rule matched: suspicious POST request')
        rules_matched += 1

    if no_host_header(request):
        report_comment = append_to_report(f'No Host header: {request.method} {request.path}\n',
            '21',
            report_categories,
            report_comment)
        logging.debug('Rule matched: no Host header.')
        rules_matched += 1
    
    # Lower the score for known researchers
    if is_research(request):
        if rules_matched > 0:
            rules_matched -= 1
    
    # If any rules matched, report it.
    if rules_matched > 0:
        reported = submit_report(report_comment, report_categories)
        logging.info(f'Reported to AbuseIPDB. Matched {rules_matched} rules')
        return reported
    else:
        reported = 0
        logging.debug('Request matched no report rules.')
        return reported
