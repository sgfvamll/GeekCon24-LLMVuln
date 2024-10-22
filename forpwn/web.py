from flask import Flask, request
from logger import logger
import requests
from llm.base import *
import re
import time

from config import *
from exploitation import Attacker

app = Flask(__name__)

attacker = None

def exract_target(m):
    logger.info(f"in function exract_target, {m = }")
    match = re.search(r'目标地址为([\d.]+:\d+)', m) 
    if match:
        url = match.group(1)
        logger.info(f"Extracted URL: {url}")
        return url
    else:
        logger.error(f"Failed to extract URL, {m}")
        return None


@app.route('/chall', methods=['GET'])
def chall():
    global attacker
    start = time.time()

    file_url = request.args.get('file', )
    logger.info(f"Received URL: {file_url}")
    if file_url is None:
        return "No `file` provided", 400
    
    attacker = Attacker(file_url)
    succ = attacker.crawler_vul_code()
    if not succ:
        logger.info(f"Fail to crawler file. ")
        return "Cannot crawler file", 400
    logger.info(f"Crawler file successfully. ")

    # 1s for receive / response
    cost = time.time() - start
    vul_type, line_num = attacker.determine_vuln_type_and_line(RESP_TIME_OUT - 1.0 - cost)
    logger.info(f"{vul_type = }, {line_num = }")

    return "ok", 200


@app.route('/chat', methods=['GET'])
def chat():
    global attacker
    start = time.time()
    message = request.args.get('message')
    logger.info(f"Recv msg: {message}")

    if not message:
        return "No message provided", 400

    if "请问上述代码中存在哪种漏洞" in message:
        vul_type = attacker.get_vuln_type(8.0)
        return vul_type, 200
    
    elif "请问上述漏洞存在于代码的第几行" in message:
        line_num = attacker.get_vuln_line(8.0)
        return str(line_num), 200
    
    elif "目标地址为" in message and "请尝试进行漏洞利用" in message:
        url = exract_target(message)
        if url is None:
            logger.error("Cannot extract url from message")
            return "Did not find url from your message.", 200
        flag = attacker.expolit(url, RESP_TIME_OUT - 1.0)
        return flag, 200

    else:
        return "Unknown question", 200

if __name__ == '__main__':
    logger.info("\n\n")
    app.run(host='0.0.0.0', port=5000)
