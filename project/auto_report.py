""" Functions related to auto-reporting. """

import logging
import datetime
import json
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
        logging.info('Success.')
        reported = 1
    return reported

# BEGIN RULES

def is_env_probing(request):
    """ Returns True if path contains any of target strings. """
    path = request.path
    env_probe_paths = ['.env', 'config', 'admin', '.git', 'backend', 'phpinfo']
    return any(target in path for target in env_probe_paths)

def is_phpmyadmin_probe(request):
    path = request.path
    pma_probe_paths = ['phpmyadmin', '/mysql/', '/sqladmin/', '/mysqlmanager/', '/myadmin/']
    return any(target in path for target in pma_probe_paths)

def is_post_request(request):
    """ Return True if POST. Any POST requests we receive are suspicious to begin with. """
    return request.method == 'POST'

def no_host_header(request):
    """ True if request contains no HOST header. """
    host_header = request.headers.get("Host")
    return host_header is None

def is_research(request):
    """ We can reduce score if it's known research orgs, don't really need to report them. """
    user_agent = request.headers.get('User-Agent')
    research_user_agents = [
        'CensysInspect',
        'Expanse, a Palo Alto Networks company',
    ]
    return any(target in user_agent for target in research_user_agents)

# END RULES

def append_to_report(comment, category, report_categories, report_comment):
    """ Append a note and category to the report params. """
    if category not in report_categories:
        report_categories.add(category)
    report_comment += comment
    return report_comment

def check_all_rules():
    #This is the command we'll call from the main route

    # Initialize these empty, then append_to_report() will fill them in if any rules match.
    report_categories = set()
    report_comment = "Honeypot detected attack:\n"

    rules_matched = 0 #This will be our "score"; if score > 0, then report it.

    # Check against our rules. There's probably a better way to do this.
    if is_env_probing(request):
        report_comment = append_to_report(f'Environment/config probing: {request.method} {request.path}\n',
            '21',
            report_categories,
            report_comment)
        rules_matched += 1
        logging.debug('Rule matched: Environment probing')

    if is_phpmyadmin_probe(request):
        append_to_report(f'PhpMyAdmin probing: {request.method} {request.path}\n',
            '21',
            report_categories,
            report_comment)
        rules_matched += 1
        logging.debug('Rule matched: PhpMyAdmin probing')

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
    
    # If no matching rules, then don't report it. Need to figure this out.
    if rules_matched > 0:
        reported = submit_report(report_comment, report_categories)
        logging.info(f'>> Reported to AbuseIPDB. Matched {rules_matched} rules')
        return reported
    else:
        reported = 0
        logging.debug('Request matched 0 reporting rules.')
        return reported
