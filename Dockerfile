FROM ubuntu:22.04

RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list
RUN sed -i 's/security.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list
RUN apt update && apt install -y python3 python3-pip unzip

COPY . /app
RUN pip3 install -r /app/requirement.txt

RUN chmod +x /app/entry.sh

EXPOSE 5000
EXPOSE 7000
