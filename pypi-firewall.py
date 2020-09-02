#!/usr/bin/python
# -*- coding:utf-8 -*-

#############################################
# PyPI Firewall
# - Code by Jioh L. Jung (ziozzang@gmail.com)
#############################################

import io, os, sys
import http.client as httplib
import urllib.parse as urlparse

import re
import urllib
import json
import tarfile, zipfile
import threading

import subprocess
import re
import yaml
from packaging.version import Version, LegacyVersion
from packaging.specifiers import SpecifierSet

from flask import Flask, Blueprint, request, Response, url_for
from werkzeug.datastructures import Headers
from werkzeug.exceptions import NotFound

from cvsslib import cvss2, cvss3, calculate_vector

app = Flask(__name__)
lock = threading.Lock()

# Default Configuration
DEBUG_FLAG = True
LISTEN_PORT = 8080

GEMNASIUM_DB_PATH = "/opt/gemnasium-db"
if 'GEMNASIUM_DB_PATH' in os.environ.keys():
    if len(os.environ['GEMNASIUM_DB_PATH']) > 0:
        GEMNASIUM_DB_PATH = os.environ['GEMNASIUM_DB_PATH']
IGNORE_CVE_IDS = ""
if 'IGNORE_CVE_IDS' in os.environ.keys():
    if len(os.environ['IGNORE_CVE_IDS']) > 0:
        IGNORE_CVE_IDS = os.environ['IGNORE_CVE_IDS']
WHITELIST_APPS = "" #org.codehaus.plexus/plexus-utils"
if 'WHITELIST_APPS' in os.environ.keys():
    if len(os.environ['WHITELIST_APPS']) > 0:
        WHITELIST_APPS = os.environ['WHITELIST_APPS']
FLAG_SKIP_NO_CVSS_DATA = True # if True -> skipping no CVSS discovered
if 'FLAG_SKIP_NO_CVSS_DATA' in os.environ.keys():
    if len(os.environ['FLAG_SKIP_NO_CVSS_DATA']) > 0:
        FLAG_SKIP_NO_CVSS_DATA = bool(int(os.environ['FLAG_SKIP_NO_CVSS_DATA']))
CVSS_SCORE_BASELINE = "6,6,6|6,6,6" # CVSSv2 / CVSSv3
if 'CVSS_SCORE_BASELINE' in os.environ.keys():
    if len(os.environ['CVSS_SCORE_BASELINE']) > 0:
        CVSS_SCORE_BASELINE = os.environ['CVSS_SCORE_BASELINE']

TMP_BASE_PATH = "/tmp"
if 'TMP_BASE_PATH' in os.environ.keys():
    if len(os.environ['TMP_BASE_PATH']) > 0:
        TMP_BASE_PATH = os.environ['TMP_BASE_PATH']

# Load Gemnasium DB(git) to Memory
def convert_generic_verstr(q):
  res = ""
  for i in q.split("||"):
    i = i.strip()
    if len(res) > 0: res += "||"
    res += ",".join(i.split())
  return res


cve_ids = []


def load_ignorence_cve_ids():
    global cve_ids, IGNORE_CVE_IDS
    cve_ids = []
    for i in IGNORE_CVE_IDS.split(","):
        cve_ids.append(i.strip())


def check_cvss_baseline(i):
  if FLAG_SKIP_NO_CVSS_DATA and (('cvss_v3' not in i.keys()) and ('cvss_v2' not in i.keys())):
    return False
  c2,c3 = CVSS_SCORE_BASELINE.split("|")
  bc2 = c2.split(",")
  bc3 = c3.split(",")
  if 'cvss_v2' in i.keys():
    t = calculate_vector(i['cvss_v2'], cvss2)
    for j in range(3):
      if t[j] is None:
        continue
      if t[j] >= float(bc2[j]):
        return True
  if 'cvss_v3' in i.keys():
    t = calculate_vector(i['cvss_v3'], cvss3)
    for j in range(3):
      if t[j] is None:
        continue
      if t[j] >= float(bc3[j]):
        return True
  return False

def print_cvss_score(target):
  if 'cvss_v2' in target.keys():
    r = calculate_vector(target['cvss_v2'], cvss2)
    print (r)
    app.logger.info(">> CVSS V2: Score: %s" % (str(r),))
    app.logger.info(">> CVSS V2: Vector: %s" % (str(target['cvss_v2']),))
  if 'cvss_v3' in target.keys():
    r = calculate_vector(target['cvss_v3'], cvss3)
    print (r)
    app.logger.info(">> CVSS V3: Score: %s" % (str(r),))
    app.logger.info(">> CVSS V3: Vector: %s" % (str(target['cvss_v3']),))
    
# Loading Gemnasium Database
gem_db = {}
def load_gemnasium_db():
  gdb = {} # Clear All
  for i in subprocess.getoutput("find %s/pypi/ | grep '.yml'" % (GEMNASIUM_DB_PATH,)).splitlines():
    if not i.endswith(".yml"): continue
    d = yaml.load(open(i), Loader=yaml.FullLoader)
    if not 'package_slug' in d.keys():
      continue
    c = d['package_slug'].split('/',1)
    if not c[0] in gdb.keys(): gdb[c[0]] = {}
    d['affected_range_original'] = d['affected_range']
    d['affected_range'] = convert_generic_verstr(d['affected_range'])
    if c[1].lower() not in gdb[c[0]].keys():
      gdb[c[0]][c[1].lower()] = []
    gdb[c[0]][c[1].lower()].append(d)
  return gdb

def is_affected(names, versions, types="pypi"):
    # TODO: https://github.com/ctxis/cvsslib -> needed to check CVSS score
    if names.lower().strip() in WHITELIST_APPS.lower().split(","):
        app.logger.info(">> Whitelisted: %s" %(names.lower().strip(),))
        return False
    lock.acquire()
    ks = gem_db[types].keys()
    lock.release()
    if names.lower().strip() not in ks:
        app.logger.info(">> No Known Security issues on DB: %s" %(names.lower().strip(),))
        return False
    res = False
    lock.acquire()
    for target in gem_db[types][names.lower()]:
        if target['identifier'] in cve_ids:
            app.logger.info("> CVE ID is whitelisted: %s" % (target['identifier'],))
            continue
        if not check_cvss_baseline(target):
            app.logger.info("> CVE Baseline is passed: %s[%s]" % (names, versions))

            print_cvss_score(target)
            continue
        if versions in target['fixed_versions']:
            res = res or False
        for i in target['affected_range'].split("||"):
            if versions in SpecifierSet(i.strip()):
                app.logger.info("> ID: %s\n> Notes: %s" % (target['identifier'], target['title']))
                #print(target)
                print_cvss_score(target)
                res = True
                break
    lock.release()
    return res

##############
proxy = Blueprint('proxy', __name__)


@proxy.route('/reload/', methods=["GET"])
def force_reload():
  global gem_db
  lock.acquire()
  gem_db = load_gemnasium_db()
  lock.release()
  return "Reloaded"

# pypi started from /pypi/
@proxy.route('/', methods=["GET"])
@proxy.route('/simple', methods=["GET"])
@proxy.route('/simple/', methods=["GET"])
@proxy.route('/simple/<path:file>', methods=["GET"])
@proxy.route('/pypi/', methods=["GET"])
@proxy.route('/pypi/<path:file>', methods=["GET"])
def pypi_request(file=""):
  hostname = "pypi.org" # Fixed value
  #print ("F: '%s'" % (file))

  request_headers = {}
  for h in ["Cookie", "Referer", "X-Csrf-Token"]:
    if h in request.headers:
      request_headers[h] = request.headers[h]

  if request.query_string: path = "/simple/%s?%s" % (file, request.query_string)
  else: path = "/simple/" + file

  # only for GET method
  form_data = None

  conn = httplib.HTTPSConnection(hostname, 443)
  conn.request(request.method, path, body=form_data, headers=request_headers)
  resp = conn.getresponse()


  # Clean up response headers for forwarding
  d = {}
  response_headers = Headers()
  for key, value in resp.getheaders():
    #print ("HEADER: '%s':'%s'" % (key, value))
    d[key.lower()] = value
    if key in ["content-length", "connection", "content-type"]: continue

    if key == "set-cookie":
      cookies = value.split(",")
      [response_headers.add(key, c) for c in cookies]
    else:
      response_headers.add(key, value)

  # Replace to match URL
  contents = resp.read() \
          .replace(b'href="/simple/',b'href="/pypi/') \
          .replace(b'href="https://files.pythonhosted.org/packages/',b'href="/packages/')
  d['content-length'] = len(contents)

  #print (type(contents))

  flask_response = Response(response=contents,
                            status=resp.status,
                            headers=d)
  return flask_response


@proxy.route('/packages/', methods=["GET"])
@proxy.route('/packages/<path:file>', methods=["GET"])
def packages_request(file=""):
  hostname = "files.pythonhosted.org" # Fixed value
  app.logger.info ("F: '%s'" % (file))

  request_headers = {}
  for h in ["Cookie", "Referer", "X-Csrf-Token"]:
    if h in request.headers:
      request_headers[h] = request.headers[h]

  if request.query_string: path = "/packages/%s?%s" % (file, request.query_string)
  else: path = "/packages/" + file
  app.logger.info(path)

  # only for GET method
  form_data = None

  conn = httplib.HTTPSConnection(hostname, 443)
  conn.request(request.method, path, body=form_data, headers=request_headers)
  resp = conn.getresponse()


  # Clean up response headers for forwarding
  d = {}
  response_headers = Headers()
  for key, value in resp.getheaders():
    #print ("HEADER: '%s':'%s'" % (key, value))
    d[key.lower()] = value
    if key in ["content-length", "connection", "content-type"]: continue

    if key == "set-cookie":
      cookies = value.split(",")
      [response_headers.add(key, c) for c in cookies]
    else:
      response_headers.add(key, value)

  pkg_name, pkg_version, meta_file, meta_contents = "", "", "", None
  # Replace to match URL
  contents = resp.read()
  if path.endswith(".whl"):
    z = zipfile.ZipFile(io.BytesIO(contents))
    for i in z.namelist():
      if i.endswith("dist-info/METADATA"):
        meta_file = i
    meta_contents = z.read(meta_file).decode("utf-8")
  elif path.endswith(".tar.gz") or path.endswith(".tgz"):
    z = tarfile.open(fileobj=io.BytesIO(contents))
    for i in z.getmembers():
      if i.name.endswith('/PKG-INFO'):
        meta_file = i.name
    meta_contents = z.extractfile(meta_file).read().decode("utf-8")
  if meta_contents is not None:
    for i in meta_contents.splitlines():
      j = i.split(":",1)
      if len(j) == 1: continue
      if j[0].lower() == "name":
        pkg_name = j[1].strip()
      if j[0].lower() == "version":
        pkg_version = j[1].strip()
  if not is_affected(pkg_name, pkg_version):
    # ClamAV scanning.
    tmp_file_name = subprocess.getoutput("mktemp -u %s/scanfile-XXXXXXXXXX" % (TMP_BASE_PATH,))
    open(tmp_file_name,"wb").write(contents)
    r = os.system("clamdscan %s > /dev/null" %(tmp_file_name,))
    os.system("rm -f %s" % (tmp_file_name,))
    if r == 0:
      app.logger.info(">> name: '%s' / version: '%s' - Not Affected" % (pkg_name, pkg_version))
      d['content-length'] = len(contents)
      flask_response = Response(response=contents,
                            status=resp.status,
                            headers=d)
    else:
      app.logger.info(">> name: '%s' / version: '%s' - ClamAV Scanning Failed / 404 Returned" % (pkg_name, pkg_version))
      flask_response = Response(response="Vulnarbility Issue Affected Version",
                            status=404)

  else:
    app.logger.info(">> name: '%s' / version: '%s' - Affected / 404 Returned" % (pkg_name, pkg_version))
    flask_response = Response(response="Vulnarbility Issue Affected Version",
                            status=404)

  return flask_response

gem_db = load_gemnasium_db()
app.register_blueprint(proxy)
app.run(debug=DEBUG_FLAG, host='0.0.0.0', port=LISTEN_PORT, threaded=True)
