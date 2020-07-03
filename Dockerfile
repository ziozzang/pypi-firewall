FROM python:3

WORKDIR /opt
COPY *.py /opt/
EXPOSE 8080
RUN pip install flask
CMD ["python3" "/opt/proxy-pypi.py"]
