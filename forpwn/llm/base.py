import asyncio

from logger import logger

def extract_from_json(data, *keys):
    if data is None:
        return (None for key in keys)
    try:
        return (data[key] for key in keys)
    except Exception as e:
        logger.error(f"Read from json data failed. ")
        return (None for key in keys)
    
def remove_backquote_in_code(code):
    '''
    Remove backquote in begin and end of code
    '''
    code = code.strip()
    if code.startswith("```") and code.endswith("```"):
        code = code.split("\n")[1:-1]
        return "\n".join(code)
    return code

class LLMSolver:
    def __init__(self, system_prompt):
        self.history = [{"role": "system", "content": system_prompt},]
        self.checkpoints = [len(self.history)]

    def commit(self):
        self.checkpoints.append(len(self.history))

    def revert(self):
        self.history = self.history[:self.checkpoints[-1]]

    def commit_or_revert(self, f):
        if f:
            self.commit()
        else:
            self.revert()

    def rollback(self):
        self.checkpoints.pop()
        self.revert()

    async def ask_for_vuln_type_and_line(self, code: str, time_limit: float) -> tuple[str, str]:
        return None, None

    async def ask_for_payload(self, url: str, vul_type:str, time_limit: float, prompt=None) -> str:
        return None

