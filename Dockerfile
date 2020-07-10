FROM python:3

WORKDIR /opt
COPY * /opt/
EXPOSE 8080
RUN pip install -r requirements.txt
CMD ["python", "/opt/pypi-firewall.py"]
