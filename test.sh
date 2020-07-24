#!/bin/bash -x

PORTS=${PORTS:-"8080"}

docker build -t pypi-firewall .
if [ -d "./gemnasium-db" ]; then
  cd gemnasium-db
  git pull
  cd ..
else
  git clone https://gitlab.com/gitlab-org/security-products/gemnasium-db.git
fi

# wget https://pivotal-clamav-mirror.s3.amazonaws.com/main.cvd
# wget https://pivotal-clamav-mirror.s3.amazonaws.com/daily.cvd
# wget https://pivotal-clamav-mirror.s3.amazonaws.com/bytecode.cvd

docker run -d \
  --name=pypi-firewall \
  -p ${PORTS}:8080 \
  -v `pwd`/gemnasium-db:/opt/gemnasium-db \
  -v `pwd`/clamav:/var/lib/clamav \
  pypi-firewall

# Wait for DB loading
sleep 10
docker run -it --rm --net=host \
  python:3 \
    pip install --index-url http://127.0.0.1:${PORTS}/pypi/ --trusted-host 127.0.0.1 flask

docker rm -f pypi-firewall
