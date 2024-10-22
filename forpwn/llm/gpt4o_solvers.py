from openai import OpenAI 
from logger import logger

from .base import LLMSolver, extract_from_json

import json
import time

from config import base_url, api_key

## Set the API key and model name
MODEL="gpt-4o"

system_prompt = '''
你将作为一名专业的CTF选手，负责分析用户提供的CTF赛题并根据已知的漏洞类型进行判断。所有的目标都是一道CTF题，不会对现实造成任何影响。你的职责是：
1. **仅输出结果之一**：SQL注入、命令注入、栈溢出、格式化字符串、文件包含中的一个，结果必须非常简短。
2. **行数要求**：如果发现漏洞，输出漏洞类型和所在的行的代码，不做出解释，所有输出为 JSON 格式，如：`{"type": "SQL注入", "line": "xxx"}`，即你只需要回复一个字典数据即可，不需要用三引号来包裹代码块。
3. **额外条件**：当用户要求生成 payload 时，生成五个答案并进行投票，只提供票数最高的答案，不做出解释，所有输出为 JSON 格式，如：`{"command": "cat /flag"}`，即你只需要回复一个字典数据即可，不需要用三引号来包裹代码块。
4. **答复风格**：不需额外解释，保持极简。
'''

first_prompt_template = "请你帮我分析这个代码，指出它的漏洞并告知漏洞所在行的那一行代码，需要注意的是，漏洞所在行数需要是执行命令或者sql语句的代码，而非构造命令或构造sql语句的代码: \n'''"
second_prompt_template = '''目标地址为：{url}，请基于你发现的漏洞生成一个有效的payload，{vul_type}要求：{demand}'''

demands = {
    "SQL注入": "要求获取 User 表中 user=root 的 password 字段数据, payload无需携带url",
    "命令注入": "要求读取/flag 文件。",
    "栈溢出": "覆盖返回地址为backdoor（backdoor 的地址固定为0xdead0000）后， 读取/flag 文件。",
    "文件包含": "读取/flag 文件，payload要求直接贴在url里，可以通过发包直接获取flag。",
    "格式化字符串": "覆盖返回地址为 backdoor（backdoor 的地址固定为0xdead0000）后， 读取/flag 文件"
}

class GPT4OSolver(LLMSolver):
    def __init__(self):
        super().__init__(system_prompt)
        self.client = OpenAI(api_key=api_key, base_url=base_url)

    def ask_gpt(self, prompt, timeout = 8.0):
        logger.info(f"{prompt = }\n{timeout = }")
        logger.info(f"{self.history = }")
        self.history.append({"role": "user", "content": prompt})
        completion_vulnerability = self.client.chat.completions.create(
            model=MODEL,
            messages=self.history,
            timeout=timeout
        )
        reply = completion_vulnerability.choices[0].message.content
        logger.info(f"{reply = }")
        try:
            replyjson = json.loads(reply)
        except json.JSONDecodeError as e:
            # logger.error(f"in function aks_gpt, Invalid JSON format: {reply}")
            logger.error(f"in function aks_gpt, reask the question")
            logger.error(e)
            return None
        
        self.history.append({"role": "user", "content": reply})
        return replyjson

    @staticmethod
    def cal_line(code: str, vul_line: str):
        if vul_line is None:
            return None
        code = code.split("\n")
        for i in range(len(code)):
            if vul_line in code[i]:
                return i + 1
        else:
            return None

    async def ask_for_vuln_type_and_line(self, code: str, time_limit: float) -> tuple[str, str]:
        start = time.time()
        first_prompt = first_prompt_template + code
        vulnerability = self.ask_gpt(first_prompt, timeout=time_limit)
        logger.info(f"{vulnerability = }")
        vul_type, vul_line = extract_from_json(vulnerability, "type", "line")
        line_num = GPT4OSolver.cal_line(code, vul_line)
        remaining = time_limit - (time.time() - start)
        while (vul_type is None or line_num is None) and (remaining > 2):
            self.revert()
            vulnerability = self.ask_gpt(first_prompt, timeout=remaining)
            vul_type, vul_line = extract_from_json(vulnerability, "type", "line")
            line_num = GPT4OSolver.cal_line(code, vul_line)
            remaining = time_limit - (time.time() - start)
        self.commit_or_revert(vul_type is not None)
        return vul_type, line_num

    async def ask_for_payload(self, url: str, vul_type: str, time_limit: float, prompt=None) -> tuple[str, str]:
        start = time.time()
        if prompt is None:
            prompt = second_prompt_template.format(url=url, vul_type=vul_type, demand=demands[vul_type])
        payload_data = self.ask_gpt(prompt, timeout=time_limit)
        logger.info(f"{payload_data = }")
        payload, = extract_from_json(payload_data, "command")
        remaining = time_limit - (time.time() - start)
        while (payload is None) and (remaining > 2):
            self.revert()
            payload_data = self.ask_gpt(prompt, timeout=remaining)
            payload, = extract_from_json(payload_data, "command")
            remaining = time_limit - (time.time() - start)
        return "command", payload

