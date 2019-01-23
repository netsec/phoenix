import argparse
import sys
import os
import django
import subprocess
import string
import ssl

from random import *
##TODO Degrease
sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "web"))
sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "web", "web"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
from django.conf import settings

from lib.cuckoo.common.config import Config
config = Config("reporting")
options = config.get("z_misp")
mymisp = options["url"]
auth_key = options["apikey"]
htpasswd_file = '/etc/apache2/.cuckoo'
gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
mycwd = os.getcwd()
characters = string.ascii_letters + string.punctuation + string.digits
characters.replace('!', '')


def generate_password():
    return "".join(choice(characters) for x in range(randint(16, 16)))


def createDjango(email, pw, groups):
    ## Needed for groups to work
    # Import here so that we don't waste time with the script at startup
    from django.contrib.auth.models import User
    from django.contrib.auth.models import Group
    django.setup()
    ## Create the user
    user = User.objects.create_user(email, email, pw)
    user.save()
    ## Add the user to groups
    if groups:
        for group in groups:
            my_group = Group.objects.get(name=group)
            my_group.user_set.add(user)

def createMoloch(email, pw):
    ## Add the user to Moloch
    os.chdir('/data/moloch/viewer')
    process = subprocess.Popen('../bin/node addUser.js "'+email+'" "'+email+'" "'+pw+'"', shell=True, stdout=subprocess.PIPE)
    process.wait()

def createApache2(email, pw, htpasswd_file):
    ## Add the user to apache2
    os.chdir(mycwd)
    process = subprocess.Popen('htpasswd -b '+htpasswd_file+' "'+email+'" "'+pw+'"', shell=True, stdout=subprocess.PIPE)
    process.wait()


def create_misp(email, pw, groups):
    # Import here to not waste time in script
    from pymisp import PyMISP
    misp = PyMISP(mymisp, auth_key, False)
    org = misp.add_organisation(email)
    check_misp_errors(org,"Error adding organisation")

    org_id = org["Organisation"]["id"]
    user = misp.add_user(email, org_id, 4, password=pw)
    check_misp_errors(user, "Error adding user")

    sharing_groups_response = misp.get_sharing_groups()
    check_misp_errors(sharing_groups_response, "Error getting sharing groups")
    if groups:
        sharing_groups = {group["SharingGroup"]["name"]: group["SharingGroup"]["id"] for group in sharing_groups_response}
        for group in groups:
            if group in sharing_groups:
                misp.sharing_group_org_add(sharing_groups[group], org_id)


def check_misp_errors(response, error_str):
    if "errors" in response:
        raise Exception("{0}: {1}".format(error_str,response["errors"][-1]))


def success(email):
    return ('''Time to send this disclaimer to your new user: ''' + email +
    '''\n By using this system in any capacity or capability, you release all claims of damages and shall not hold or perceive any liability against the publisher for:  damage, unexpected events or results, decision, or reputation damage, even those resulting from wilful or intentional neglect.  No claims made against this data shall be honored; no assertions have been made about the quality, accuracy, usability, actionability, reputation, merit, or hostility of the returned findings.  Use the returned results at your own risk.  In no event will the publisher be liable for any damages whatsoever arising out of or related to this output, any website or service or output operated by a third party or any information contained in this output or any other medium, including, but not limited to, direct, indirect, incidental, special, consequential or punitive damages, including, but not limited to, lost data, lost revenue, or lost profits, under any theory, whether under a contract, tort (including negligence) or any other theory of liability, even if the publisher is aware of the possibility of such damages.  By using this service, you agree to pursue no legal action in any form for any reason.  You may not use this data to source information about a competing party for leverage or competitive advantage.

There are 4 instances where you will need to use the password:
The front door apache server (this keeps bots away quite well)
The cuckoo django instance
The moloch instance
The MISP instance

Please report all bugs to me with the subject line of 'Phoenix Bugs'.''')


def main():
    parser = argparse.ArgumentParser(description='Phoenix user add script')
    parser.add_argument("email", help='Email to add')
    parser.add_argument('-g', '--groups', nargs='+', help='Groups to add the email to - space separated')
    parser.add_argument('-p', '--password', help='Optional, set the password manually')
    settings = parser.parse_args()
    email = settings.email
    groups = settings.groups
    pw = settings.password

    if not pw:
        pw = generate_password()
    # groups = groups.split(',')

    createDjango(email, pw, groups)
    createMoloch(email, pw)
    createApache2(email, pw, htpasswd_file)
    create_misp(email, pw, groups)
    print success(email)
    print str(pw)

##TODO Add the user as an ORG in MISP

if __name__ == "__main__":
    main()