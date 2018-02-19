from __future__ import print_function

from argparse import ArgumentParser
from bs4 import BeautifulSoup
import json
import requests
import sys
EMPTYSTRING=""

class SiteReview(object):
    def __init__(self):
        self.baseurl = "http://sitereview.bluecoat.com/rest/categorization"
        self.useragent = {"User-Agent": "Mozilla/5.0"}

    def sitereview(self, url):
        payload = {"url": url}

        self.req = requests.post(
            self.baseurl,
            headers=self.useragent,
            data=payload
        )
        return json.loads(self.req.content.decode("UTF-8"))

    def check_response(self, response):
        if self.req.status_code != 200:
            raise Exception("[-] HTTP {} returned".format(req.status_code))

        elif "error" in response:
            raise Exception(response["error"])

        else:
            self.category = BeautifulSoup(response["categorization"], "lxml").get_text()
            self.date = BeautifulSoup(response["ratedate"], "lxml").get_text()[0:35]
            self.url = response["url"]


def bluecoat_sitereview(url):
    s = SiteReview()
    try:
        response = s.sitereview(url)
        s.check_response(response)
        return s.category
    except Exception as e:
        print(e)
        return EMPTYSTRING


if __name__ == "__main__":
    p = ArgumentParser()
    p.add_argument("url", help="Submit domain/URL to Blue Coat's Site Review")
    args = p.parse_args()

    bluecoat_sitereview(args.url)
