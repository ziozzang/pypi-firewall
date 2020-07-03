FROM python:3

WORKDIR /opt
COPY *.py /opt/
EXPOSE 8080
RUN pip install pyyaml flask packaging
CMD ["python", "/opt/proxy-pypi.py"]
