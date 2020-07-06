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

import subprocess
import re
import yaml
from packaging.version import Version, LegacyVersion
from packaging.specifiers import SpecifierSet

from flask import Flask, Blueprint, request, Response, url_for
from werkzeug.datastructures import Headers
from werkzeug.exceptions import NotFound

app = Flask(__name__)

# Default Configuration
DEBUG_FLAG = False
LISTEN_PORT = 8080

GEMNASIUM_DB_PATH = "/opt/gemnasium-db"

# Load Gemnasium DB(git) to Memory
def convert_generic_verstr(q):
  res = ""
  for i in q.split("||"):
    i = i.strip()
    if len(res) > 0: res += "||"
    res += ",".join(i.split())
  return res

# Loading Gemnasium Database
gem_db = {}
def load_gemnasium_db():
  global gem_db
  gem_db = {} # Clear All
  for i in subprocess.getoutput("find %s/pypi/ | grep '.yml'" % (GEMNASIUM_DB_PATH,)).splitlines():
    if not i.endswith(".yml"): continue
    d = yaml.load(open(i), Loader=yaml.FullLoader)
    if not 'package_slug' in d.keys():
      continue
    c = d['package_slug'].split('/',1)
    if not c[0] in gem_db.keys(): gem_db[c[0]] = {}
    d['affected_range_original'] = d['affected_range']
    d['affected_range'] = convert_generic_verstr(d['affected_range'])
    if c[1].lower() not in gem_db[c[0]].keys():
      gem_db[c[0]][c[1].lower()] = []
    gem_db[c[0]][c[1].lower()].append(d)

def is_affected(names, versions, types="pypi"):
  if names.lower() not in gem_db[types].keys():
    return False
  target = gem_db[types][names.lower()]
  if versions in target['fixed_versions']:
    return False
  for i in target['affected_range'].split("||"):
    if versions in SpecifierSet(i.strip()):
      return True
  return False

##############
proxy = Blueprint('proxy', __name__)

# pypi started from /pypi/
@proxy.route('/', methods=["GET"])
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

  print (type(contents))


  flask_response = Response(response=contents,
                            status=resp.status,
                            headers=d)
  return flask_response


@proxy.route('/packages/', methods=["GET"])
@proxy.route('/packages/<path:file>', methods=["GET"])
def packages_request(file=""):
  hostname = "files.pythonhosted.org" # Fixed value
  print ("F: '%s'" % (file))

  request_headers = {}
  for h in ["Cookie", "Referer", "X-Csrf-Token"]:
    if h in request.headers:
      request_headers[h] = request.headers[h]

  if request.query_string: path = "/packages/%s?%s" % (file, request.query_string)
  else: path = "/packages/" + file
  print(path)

  # only for GET method
  form_data = None

  conn = httplib.HTTPSConnection(hostname, 443)
  conn.request(request.method, path, body=form_data, headers=request_headers)
  resp = conn.getresponse()


  # Clean up response headers for forwarding
  d = {}
  response_headers = Headers()
  for key, value in resp.getheaders():
    print ("HEADER: '%s':'%s'" % (key, value))
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
    print(">> name: '%s' / version: '%s' - Not Affected" % (pkg_name, pkg_version))
    d['content-length'] = len(contents)
    flask_response = Response(response=contents,
                            status=resp.status,
                            headers=d)
  else:
    print(">> name: '%s' / version: '%s' - Affected / 404 Returned" % (pkg_name, pkg_version))
    flask_response = Response(response="Vulnarbility Issue Affected Version",
                            status=404)

  return flask_response

load_gemnasium_db()
app.register_blueprint(proxy)
app.run(debug=DEBUG_FLAG, host='0.0.0.0', port=LISTEN_PORT)
