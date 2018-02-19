from settings import *
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'cuckoo.sqlite',
    }
}

ANALYSES_PREFIX = '/home/greg/analyses/'
SURICATA_PATH = os.path.join(CUCKOO_PATH, 'docker','suricata','suricata.yaml')
YARA_DOCKER_IMAGE = 'devyara'
SURICATA_DOCKER_IMAGE = 'devsuricata'