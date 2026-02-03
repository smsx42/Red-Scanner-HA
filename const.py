from dotenv import load_dotenv
import os

load_dotenv()

IP_RANGE = os.getenv("IP_RANGE", "192.168.0.0/24")