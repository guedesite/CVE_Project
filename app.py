from dotenv import load_dotenv

import logging
import asyncio
import multiprocessing as mp
import time
import os
from multiprocessing.synchronize import Lock as SyncLock
from controller.httpServer import HttpServer
from controller.fetch.data_services_nvd_nist_gov import Data_services_nvd_nist_gov

from controller.conSources import start_cron_sources

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DATA_PATH = "cve_data.parquet"

sources = [Data_services_nvd_nist_gov()]

def start_http_server(datalake_lock:SyncLock):
    dir = os.getenv("http_server_dir")
    host = os.getenv("http_server_host")
    port = int(os.getenv("http_server_port"))

    server = HttpServer(dir, host, port, datalake_lock, DATA_PATH)
    server.start_server()


async def main() -> None:
    logger.info("Starting CVE Project ...")

    mp.set_start_method('spawn', force=True)

    manager = mp.Manager()
    datalake_lock = manager.Lock() # used to thread safe access to the datalake


    logger.info("Starting HTTP Server ...")
    web_process = mp.Process(
        target=start_http_server,
        args=(datalake_lock,),
        daemon=True,
        name="Web-Server"
    )
    web_process.start()

    logger.info("Starting Cron Sources ...")
    start_cron_sources(sources, datalake_lock, DATA_PATH)

    # process management
    processes = [
        ("Web-Server", web_process),
    ]
    try:
        # Block main thread - keep running until interrupted
        while True:
            flag = False
            time.sleep(0.1)  # Small sleep to prevent high CPU usage
            for name, process in processes:
                if not process.is_alive():
                    logger.error(f"Process {name} died unexpectedly")
                    flag = True
                    break
            if flag:
                break
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")

    # close all remaining process
    for name, process in processes:
        if process is not None and process.is_alive():
            logger.info(f"Terminating {name} process...")
            process.terminate()
            process.join(timeout=5)

            if process.is_alive():
                logger.warning(f"{name} process didn't terminate gracefully, killing...")
                process.kill()
                process.join(timeout=2)

                if process.is_alive():
                    logger.error(f"Failed to kill {name} process")
                else:
                    logger.info(f"{name} process killed successfully")
            else:
                logger.info(f"{name} process terminated successfully")

    logger.info("out.")

if __name__ == "__main__":
    asyncio.run(main())