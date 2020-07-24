FROM python:3

WORKDIR /opt
COPY * /opt/
EXPOSE 8080
RUN apt update && apt install -fy clamav clamav-daemon && \
    pip install -r requirements.txt
CMD ["bash", "/opt/startup.sh"]
