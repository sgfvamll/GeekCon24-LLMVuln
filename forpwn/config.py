
import os
from dotenv import load_dotenv

load_dotenv()

base_url = os.getenv("BASE_URL")
api_key = os.getenv("API_KEY")

RESP_TIME_OUT = 10.0

