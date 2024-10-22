import asyncio
import subprocess

from concurrent.futures import ThreadPoolExecutor
from threading import Timer

from logger import logger

executor = ThreadPoolExecutor(max_workers=10)

async def wait_async_tasks(tasks, timeout):
    tasks = [asyncio.create_task(task) for task in tasks]
    return await asyncio.wait(tasks, timeout=timeout)

def run_async_tasks(tasks, timeout):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(wait_async_tasks(tasks, timeout))
    return results


async def async_popen(cmd, timeout):
    p = await asyncio.create_subprocess_shell(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timer = Timer(timeout, p.kill)
    try:
        timer.start()
        output, err = await p.communicate()
    except Exception as e:
        logger.error(e)
        output, err = "", "Timeout"
    finally:
        timer.cancel()
    return output, err