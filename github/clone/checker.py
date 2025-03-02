# cleanup_daemon.py
import os
import json
import time
import stat
import shutil
import logging
import platform
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure logging
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'cleanup_daemon.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ExpirationFileHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback
        
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith("expirations.json"):
            logger.info("Detected changes in expirations file")
            self.callback()

class FileLock:
    """Cross-platform file lock using lock files"""
    def __init__(self, filename):
        self.lockfile = f"{filename}.lock"
        self.fd = None
        
    def __enter__(self):
        while True:
            try:
                self.fd = os.open(self.lockfile, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                break
            except FileExistsError:
                time.sleep(0.1)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.fd:
            os.close(self.fd)
        if os.path.exists(self.lockfile):
            os.remove(self.lockfile)

def _handle_remove_error(func, path, exc_info):
    """Handle Windows file removal permissions"""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception as e:
        logger.error(f"Failed to remove {path}: {e}")

def _rmtree(path):
    """Cross-platform directory removal"""
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            file_path = os.path.join(root, name)
            try:
                os.chmod(file_path, stat.S_IWRITE)
                os.unlink(file_path)
            except Exception as e:
                logger.error(f"Error removing file {file_path}: {e}")
        for name in dirs:
            dir_path = os.path.join(root, name)
            try:
                os.rmdir(dir_path)
            except Exception as e:
                logger.error(f"Error removing directory {dir_path}: {e}")
    try:
        shutil.rmtree(path, onerror=_handle_remove_error)
    except Exception as e:
        logger.error(f"Final removal error for {path}: {e}")

def cleanup_loop(base_dir="clone_repo", check_interval=30):
    expiration_file = os.path.join(base_dir, "expirations.json")
    
    # setting up file watcher
    event_handler = ExpirationFileHandler(lambda: check_expirations(immediate=True))
    observer = Observer()
    observer.schedule(event_handler, base_dir, recursive=False)
    observer.start()
    
    def check_expirations(immediate=False):
        nonlocal last_check
        if immediate or (time.time() - last_check) >= check_interval:
            perform_cleanup()
            last_check = time.time()
    
    def perform_cleanup():
        try:
            with FileLock(expiration_file):
                if not os.path.exists(expiration_file):
                    return

                with open(expiration_file, 'r') as f:
                    data = json.load(f)
                
                now = datetime.now()
                to_remove = []
                
                for repo_path, exp_time_str in data.items():
                    try:
                        if not os.path.exists(repo_path):
                            to_remove.append(repo_path)
                            continue
                            
                        exp_time = datetime.fromisoformat(exp_time_str)
                        if now > exp_time:
                            logger.info(f"Attempting to delete: {repo_path}")
                            _rmtree(repo_path)
                            logger.info(f"Successfully deleted: {repo_path}")
                            to_remove.append(repo_path)
                    except Exception as e:
                        logger.error(f"Error processing {repo_path}: {str(e)}")
                        time.sleep(1)
                
                if to_remove:
                    new_data = {k:v for k,v in data.items() if k not in to_remove}
                    with open(expiration_file, 'w') as f:
                        json.dump(new_data, f)
                        
        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")
    
    last_check = time.time()
    
    try:
        while True:
            check_expirations()
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    logger.info("Starting cleanup daemon...")
    try:
        cleanup_loop(check_interval=30)
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}")
    logger.info("Cleanup daemon stopped")