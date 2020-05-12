
import argparse
import validators
import requests
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment

parser = argparse.ArgumentParser(description='Mel\'s Vulnerability Analyzer v1.0')

parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help='the url to be validated')
parser.add_argument('--config', help='path to configuration file')
parser.add_argument('-o', '--output', help='Report file output path')

args = parser.parse_args()
config = {'forms': True, 'comments': True, 'passwords': True}

if args.config:
    print("Using config file: "+ args.config)
    config_file = open(args.config, 'r')
    config_from_file = yaml.load(config_file)
    if config_from_file:
        config = {**config, **config_from_file} # ** = to expand to full dict

report = ""
url = args.url #grabs url input in the req positional argument

if validators.url(url):
    result_html = requests.get(url).text #convert into text form
    parsed_html = BeautifulSoup(result_html, 'html.parser') #put in bs constructor


    forms           = parsed_html.find_all('form')
    comments        = parsed_html.find_all(string=lambda text:isinstance(text,Comment))
    password_inputs = parsed_html.find_all('input', {'name' : 'password'})

    if config['forms']:
        for form in forms:
            if form.get('action').find('https') < 0 and urlparse(url).scheme != 'https':
                report += 'Form Issue: Insecure form ' + form.get('action') + ' found in document\n'
                
    if config['comments']:
        for comment in comments:
            if comment.find('key: ') > -1:
                report += "Comment Issue: Key is found in the HTML comments, please remove\n"

    if config['passwords']:
        for password_input in password_inputs:
            if password_input.get('type') != 'password':
                report += 'Input Issue: Plain text password input found. Please change to password\n'

else:
    print("Invalid URL. Please include full URL scheme.")

if(report == ''):
  report += 'Nice job! Your HTML document is secure!\n'
else:
  header =  'Vulnerability Report is as follows:\n'
  header += '==================================\n\n'

  report = header + report

print(report)

if(args.output):
  f = open(args.output, 'w')
  f.write(report)
  f.close
  print('Report saved to: ' + args.output)
