# pypi-firewall
* This is PyPI firewalled proxy server with real-time checking vulnerability database by Gemnasium (GitLab). 
* if you request some library with vulnerability issue, server block request. otherwise, it will pass your request.

# How to use

* Set PyPI env.

```
cat > ~/.pypirc <<EOL
[distutils]
index-servers =
  local

[local]
repository: http://127.0.0.1:8080/pypi/
EOL
```

* or force use on CLI.

```
pip install --index-url http://127.0.0.1:8080/pypi/ --trusted-host 127.0.0.1 flask

# to use proxy with nexus
pip install --index-url http://127.0.0.1:8081/repository/pypi/simple --trusted-host 127.0.0.1 flask

# to ignore big-file timeout, use option like '--timeout 1800'
```

# Setup Server

```
git clone https://github.com/ziozzang/pypi-firewall.git
docker build -t pypi-firewall pypi-firewall/

git clone https://gitlab.com/gitlab-org/security-products/gemnasium-db.git
docker run -d \
  --name=pypi-firewall \
  -p 8080:8080 \
  -v `pwd`/gemnasium-db:/opt/gemnasium-db \
  pypi-firewall
```

