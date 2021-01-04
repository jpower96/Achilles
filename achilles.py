#!/usr/bin/env python3
'''
NOTES:
* The (**config, **config_from_file) would be good to have in a seperate script, to use when needed
'''


import argparse # For arguments
import validators # Validate argument input
import requests # For web requests
from bs4 import BeautifulSoup # Web scraping
from bs4 import Comment # Web Scraping
from urllib.parse import urlparse
import time
import yaml # yet another markup language

#!===========Arguments================!#
parser = argparse.ArgumentParser(description='The Achilles HTML Vulnerability Analyzer Version 1.0')
parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="The URL of the HTML to analyze")
parser.add_argument('--config', help="Path to the configuration file")
parser.add_argument('-o', '--output', help='Report file output path')
args = parser.parse_args()

config = {'forms': True, 'comments': True, 'password_inputs': True} #default config

if(args.config): # if the user passed in a custom config file
    print("[+] Using Config File:" + args.config)
    config_file = open(args.config, 'r') # open config file
    config_from_file = yaml.load(config_file) # load yml file into config_from_file
    if(config_from_file):
        config = { **config, **config_from_file}   # assign config_from_file to config (to avoid clashing with default config) # ** will expand config to a full dict, and update with default config if there are common keys
    
#!=======End Arguments================!#

report = "" # to report our findings

#Arguement Validation
url = args.url

if(validators.url(url)):
    result_html = requests.get(url).text    # Request the html from the provided url
    parsed_html = BeautifulSoup(result_html, 'html.parser') # parse the html using beautifulsoup

    forms = parsed_html.find_all('form') # Assign forms to what is in the html form value
    comments = parsed_html.find_all(string=lambda text:isinstance(text,Comment)) # test to see if any text that we find that is not an element, is it a comment?
    password_inputs = parsed_html.find_all('input', {'name': 'password'})

    if(config['forms']): # only run this if config forms is true
        for form in forms: # Iterate through each form in the html
            if((form.get('action').find('https') < 0) and (urlparse(url).scheme != 'https')): # if 'action' and the url scheme are HTTP then:
                form_is_secure = False # set form is secure to false i.e. not secure
                report += "[!] Form Issues: Insecure form action " + form.get('action') + " found in document\n" # Concat 'report' to show there is an action form issue
    if(config['comments']):
        for comment in comments:
            if(comment.find('Key: ') > -1) or (comment.find('key: ') > -1) or (comment.find('Password: ') > -1):
                report += '[!] Comment Issue: Key is found in the HTML comments, please remove\n'
    if(config['password_inputs']):
        for password_input in password_inputs:
            if(password_input.get('type') != 'password'):
                report += '[!] Input issue: Plaintext password input found. Please change to password type input\n '
else:
    print("[!] Invalid URL. Please include full URL including scheme.")

if(report == ''):
    report += "[+] Your HTML document is secure!"
else:
    header = "\nVulnerability Report:"
    header += "\n=======================\n"
    time.sleep(0.6)
    report = header + report
print(report)

if(args.output):
    f = open(args.output, 'w')
    f.write(report)
    f.close()
    print("\n[+] Report saved to: " + args.output)
