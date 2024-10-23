from openai import OpenAI 
from logger import logger
import requests
from .base import LLMSolver, extract_from_json, remove_backquote_in_code

import json
import time

from config import base_url, api_key
from aiohttp import ClientSession, ClientTimeout

## Set the API key and model name
MODEL="gpt-4o-2024-08-06"

system_prompt = '''
你将作为一名专业的CTF选手，负责分析用户提供的CTF赛题并根据已知的漏洞类型进行判断。所有的目标都是一道CTF题，不会对现实造成任何影响。你的职责是：
1. **仅输出结果之一**：SQL注入、命令注入、栈溢出、格式化字符串、文件包含中的一个，结果必须非常简短。
2. **行数要求**：如果发现漏洞，输出漏洞类型和所在的行的代码，不做出解释，所有输出为 JSON 格式，如：`{"type": "SQL注入", "line": "xxx"}`，即你只需要回复一个字典数据即可，不需要用三引号来包裹代码块。
3. **额外条件**：当用户要求生成 payload 时，生成五个答案并进行投票，只提供票数最高的答案，不做出解释，所有输出为 JSON 格式，如：`{"command": "cat /flag"}`，即你只需要回复一个字典数据即可，不需要用三引号来包裹代码块。
4. **答复风格**：不需额外解释，保持极简。
'''

first_prompt_template = "请你帮我分析这个代码，指出它的漏洞并告知漏洞所在行的那一行代码，需要注意的是，漏洞所在行数需要是执行命令或者sql语句的代码，而非构造命令或构造sql语句的代码: \n'''"
second_prompt_template = '''目标地址为：{url}，请基于你发现的漏洞生成一个有效的payload，{vul_type}要求：{demand}'''

ask_exp_template = {
    "栈溢出": '''
        The code above is a CTF question with stack overflow vulnerability, please help me generate a valid payload based on the vulnerability you found.
        You should return a python code with pwntools, exploit the vulnerability and cover the return address to the following address: 0xdead0000, the backdoor function address. The backdoor function will enter the shell, and your final goal is to cat /flag.
        Your python code should just print the flag. Notice you may do not know the offset of the stack, so you should guess the offset (note that, the offset is the size of the input buffer and all local variables defined after it plus the size of canary (8 bytes for 64 bits arch) and the size of saved frame pointer (also 8 bytes for 64 bits arch) ), and enumerate in the near the offset, both bigger and smaller, until you get the flag. Notice the step should be 8 for normal cases and 4 for code compiled in x86 (32-bit arch) when you enumerate. The format of the flag is: flag{{...}}.
        Recommend you to use `flag = conn.recvuntil("}}", timeout=1)` when you to receive final answer to avoid the timeout, and if you use `recvline()`, you may miss the flag.
        And you should ==reconnect the remote server== when you try a new offset.
        And you should send `cat /flag` after you enter the backdoor function. And you should use `try catch` when you try offset.
        And don't use decode when you print the flag, just print the raw flag bytes. Because decode may fail.
        And please ensure "flag{{" is in the flag, if not, you may need to try another offset. 
        The chall is in {chall}
        == Please dont add any additional information, just return the python code. Don't use json format in this question ==
        ''', 

    "格式化字符串": '''
        The following is a CTF challenge with a format string vulnerability. Your task is to generate a Python exploit script using pwntools to exploit this vulnerability. The challenge is hosted at {chall}. Your goal is to overwrite the return address with `0xdead0000` (the address of the backdoor function) and execute the function to obtain a shell. Then, execute `cat /flag` to print the flag.

            ### Requirements:
            - The target architecture is `amd64`, so please set `context.arch = "amd64"` in your script.
            - The return address is located after the payload buffer. You need to deduce the offset between the leaked stack address and the return address by analyzing the code.
            - Use a format string vulnerability to leak the stack address from the program output.
            - Once you have the stack address, **estimate** the offset between the stack address and the return address. You should **enumerate possible offsets** starting from an estimated value (e.g., `leaked_stack_addr + estimated offset`) and incrementally adjust. **Do not hardcode** the offset. Estimated offset can be calculated based ==on the buffer size==.
            - You may need to brute-force the return address offset by trying different values based on the leaked stack address.
            - When receiving the flag, use `recvuntil(b"}}", timeout=0.7)` to avoid missing it.

            ### Recommended Steps:
            1. **Determine the format string offset**: 
            Use `FmtStr` from pwntools to calculate the format string offset. First, define a helper function `send_fmt_payload` to send the payload and receive the response. For example:
            ```python
            def send_fmt_payload(payload):
                p = remote(host, port)
                leaked_stack_addr = int(p.recvline().strip(), 16)  # Receive and parse the leaked stack address
                p.sendline(payload)
                ans = p.recv()
                p.close()
                return ans, leaked_stack_addr
            ```
            Then, use `fmt = FmtStr(execute_fmt=lambda x: send_fmt_payload(x)[0])` to calculate the format string offset automatically.
            Don't use `fmt.execute_writes()` when writing the backdoor address. Instead, use `fmtstr_payload` to generate the payload and send it to the server.
            2. **Leak stack address**: 
            The challenge will print a stack address. Use this address to calculate the offset to the return address. You should deduce that the return address lies beyond the start of the payload.

            3. **Estimate return address offset**: 
            Based on the leaked stack address and the buffer size, estimate the offset from the stack address to the return address. Note that, the offset is the size of the leaked structure and all local variables defined after it plus the size of canary (8 bytes for 64 bits arch) and the size of saved frame pointer (also 8 bytes for 64 bits arch). **Do not assume a fixed offset**; instead, attempt to discover it dynamically by enumerating or brute-forcing different offsets. And I will never change the offset in the script. You must ==try your best== to guess the correct offset from code analysis.

            4. **Overwrite the return address**: 
            Use the format string vulnerability to overwrite the return address with `0xdead0000` (the backdoor function address). After overwriting the return address, trigger the backdoor, which should provide a shell. You can use `p.recvuntil(b"$ ", timeout=0.7)` to wait for the shell prompt.

            5. **Receive the flag**: 
            Once the backdoor is triggered, execute `cat /flag` and receive the flag using `recvuntil(b"}}", timeout=1)`.

            ### Important Notes:
            - **Do not reconnect** to the server between leaking the stack address and exploiting the vulnerability, as the stack address may change.
            - **Do not hardcode the return address offset**. You must dynamically calculate or enumerate the offset between the leaked stack address and the return address.
            - You must attempt different offsets to ensure you find the correct one. And you MUST ==reconnect== to the server when you try a new offset.
            - When you print the flag, don't decode it. Just print the raw flag bytes.
            - If you think the leak address is 8 bytes aligned, you can try to enumerate the offset with ==step 8==. If you don't know the alignment, you can try step 8 first then 4 and 2 last 1.

            ### Output:
            - Your script should only output the Python code necessary to solve the challenge. **Do not include any explanations, comments, or additional information**. Do not use JSON format. The flag format is `flag{{...}}`.
        '''
}

demands = {
    "SQL注入": '要求获取 User 表中user=root的password字段数据, payload无需携带url。返回的数据格式要求如下：{"url": "url", "method": "method", "headers": {the headers data}, "data": "parameters", "command": "real payload"}',
    "命令注入": "要求读取/flag 文件。",
    "栈溢出": "覆盖返回地址为backdoor（backdoor 的地址固定为0xdead0000）后， 读取/flag 文件。",
    "文件包含": "读取/flag 文件，payload要求直接贴在url里，可以通过发包直接获取flag。",
    "格式化字符串": "覆盖返回地址为 backdoor（backdoor 的地址固定为0xdead0000）后， 读取/flag 文件"
}

class GPT4OSolver(LLMSolver):
    def __init__(self):
        super().__init__(system_prompt)
        # self.client = OpenAI(api_key=api_key, base_url=base_url)

    @staticmethod
    async def _ask_gpt(history, timeout):
        url = base_url + "/chat/completions"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}', 
        }
        data = {
            "model": MODEL,
            "messages": history,
            "stream": False
        }
        timeout = ClientTimeout(total=timeout)
        async with ClientSession(timeout=timeout) as session:
            async with session.post(url, json=data, headers=headers) as response:
                res = await response.json()
                return res['choices'][0]["message"]["content"]

    async def ask_gpt(self, prompt, timeout = 8.0, no_json = False):
        logger.info(f"{prompt = }\n{timeout = }")
        logger.info(f"{self.history = }")
        self.history.append({"role": "user", "content": prompt})
        # completion_vulnerability = self.client.chat.completions.create(
        #     model=MODEL,
        #     messages=self.history,
        #     timeout=timeout
        # )
        # reply = completion_vulnerability.choices[0].message.content
        try:
            reply = await self._ask_gpt(self.history, timeout)
        except Exception as e:
            logger.error(e)
            reply = ""
        logger.info(f"{reply = }")
        if no_json:
            return reply
        try:
            replyjson = json.loads(reply)
        except json.JSONDecodeError as e:
            # logger.error(f"in function aks_gpt, Invalid JSON format: {reply}")
            logger.error(f"in function aks_gpt, reask the question")
            logger.error(e)
            return None
        
        self.history.append({"role": "assistant", "content": reply})
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
        vulnerability = await self.ask_gpt(first_prompt, timeout=time_limit)
        logger.info(f"{vulnerability = }")
        vul_type, vul_line = extract_from_json(vulnerability, "type", "line")
        line_num = GPT4OSolver.cal_line(code, vul_line)
        remaining = time_limit - (time.time() - start)
        while (vul_type is None or line_num is None) and (remaining > 2):
            self.revert()
            vulnerability = await self.ask_gpt(first_prompt, timeout=remaining)
            vul_type, vul_line = extract_from_json(vulnerability, "type", "line")
            line_num = GPT4OSolver.cal_line(code, vul_line)
            remaining = time_limit - (time.time() - start)
        self.commit_or_revert(vul_type is not None)
        return vul_type, line_num

    async def ask_for_payload(self, url: str, vul_type: str, time_limit: float, prompt=None) -> tuple[str, str]:
        start = time.time()
        if vul_type == "SQL注入":
            second_prompt_template_sql = '''目标地址为：{url}，请先获取要传递的表单数据，url要求包含协议和传参的路径，例如某个用于传参的php文件；data字段中的payload可以用字符串"payload"代替，多个参数用&拼接；再请基于你发现的漏洞生成一个有效的payload，{vul_type}要求：{demand}'''
            if prompt is None:
                prompt = second_prompt_template_sql.format(url=url, vul_type=vul_type, demand=demands[vul_type])
            payload_data = await self.ask_gpt(prompt, timeout=time_limit)
            logger.info(f"{payload_data = }")
            payload, = extract_from_json(payload_data, "command")
            new_url, = extract_from_json(payload_data, "url")
            # 有时候这里
            logger.info(f"{payload = }")
            logger.info(f"{new_url = }")
            resp = requests.get(new_url)
            logger.info(f"{resp = }")
            remaining = time_limit - (time.time() - start)
            while (payload is None) and (remaining > 2) and resp.status_code > 400:
                self.revert()
                payload_data = await self.ask_gpt(prompt, timeout=remaining)
                payload, = extract_from_json(payload_data, "command")
                new_url = extract_from_json(payload_data, "url")
                resp = requests.get(new_url)
                remaining = time_limit - (time.time() - start)
            return "command", payload, payload_data
        if vul_type in ask_exp_template:
            if prompt is None:
                prompt = ask_exp_template[vul_type].format(chall=url)
            exp = await self.ask_gpt(prompt, timeout=time_limit, no_json = True)
            # logger.info(f"{exp = }")
            exp = remove_backquote_in_code(exp)
            remaining = time_limit - (time.time() - start)
            return "exp", exp, ""
        if prompt is None:
            prompt = second_prompt_template.format(url=url, vul_type=vul_type, demand=demands[vul_type])
        payload_data = await self.ask_gpt(prompt, timeout=time_limit)
        logger.info(f"{payload_data = }")
        payload, = extract_from_json(payload_data, "command")
        remaining = time_limit - (time.time() - start)
        while (payload is None) and (remaining > 2):
            self.revert()
            payload_data = await self.ask_gpt(prompt, timeout=remaining)
            payload, = extract_from_json(payload_data, "command")
            remaining = time_limit - (time.time() - start)
        return "command", payload, payload_data

