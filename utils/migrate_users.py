import argparse
import os
import sys

import django

sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "web"))
sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "web", "web"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
from django.contrib.auth.models import User

from setup_user import create_misp, generate_password


def migrate_user(username, password):
    user = User.objects.get(username=username)
    if not user:
        raise Exception("Couldn't find user {0}".format(username))
    groups = map(lambda group: group.name, user.groups.all())
    if '@' not in username:
        raise Exception("User {0} is not an email, skipping".format(username))
    create_misp(username, password, groups)
    with open('out_user.txt', 'a+') as f:
        f.write(username + "|" + password + '\n')


def main(argv):
    django.setup()
    parser = argparse.ArgumentParser(description='Phoenix user migrate to MISP script')
    parser.add_argument('-u', '--username', help='user to migrate')
    parser_args = parser.parse_args()
    if parser_args.username:
        pw = generate_password()
        migrate_user(parser_args.username, pw)
    else:
        users = User.objects.all()
        for user in users:
            try:
                pw = generate_password()
                migrate_user(user.username, pw)
            except Exception as e:
                with open('out_error.txt', 'a+') as f:
                    f.write(e.message)
                print e.message

if __name__ == "__main__":
    main(sys.argv[1:])
