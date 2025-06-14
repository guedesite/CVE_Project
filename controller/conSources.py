import os
from multiprocessing.synchronize import Lock as SyncLock
from typing import List
import schedule
import time
import logging
import pandas as pd
import pyarrow.parquet as pq
import pyarrow as pa

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def start_cron_sources(sources: List, datalake_lock:SyncLock, DATA_PATH:str):
    delayHour = int(os.getenv("cronHour"))
    run_cron(sources, datalake_lock, 20, DATA_PATH) # run once
    schedule.every(delayHour).hours.do(lambda: run_cron(sources, datalake_lock, 1, DATA_PATH)) # run every %delayHour% hour


def run_cron(sources: List, datalake_lock:SyncLock, sinceDay:int, DATA_PATH:str):
    starting_s = time.time()
    logger.info("Fetching source:")

    for source in sources:
        df = source.fetch(sinceDay)
        with datalake_lock:
            if os.path.exists(DATA_PATH):
                existing = pd.read_parquet(DATA_PATH)
                df = pd.concat([existing, df]).drop_duplicates(subset=["cve_id"])
            table = pa.Table.from_pandas(df)
            pq.write_table(table, DATA_PATH)

    logger.info(f"Fetching took {round(time.time() - starting_s, 2)} seconds")


