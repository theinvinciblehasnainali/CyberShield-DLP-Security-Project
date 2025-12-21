import time
import requests
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from engine import scan_file_content 

# These paths now match your Dashboard's "Recent Threats" locations
WATCH_PATHS = [
    "./test_files",
    "./home/user/documents/financial",
    "./home/downloads/temp",
    "./home/network/shares/projects",
    "./home/hr/records"
]

API_URL = "http://localhost:5001/api/scan"

class DLPHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f"🚩 NEW FILE DETECTED: {event.src_path}")
            self.process_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            print(f"📝 FILE MODIFIED: {event.src_path}")
            self.process_file(event.src_path)

    def process_file(self, path):
        time.sleep(0.5)  # Allow file to be fully written
        
        # We no longer call scan_file_content(path) here.
        # This prevents the "missing 1 required positional argument" error.
        
        print(f"🔍 Event detected. Notifying Dashboard to scan: {path}")
        self.report_to_dashboard(path)

    def report_to_dashboard(self, path):
        try:
            clean_path = os.path.normpath(path)
            # Send 'type': 'Live' so it stands out in your tables
            requests.post(API_URL, json={"path": clean_path, "type": "Live"})
        except Exception as e:
            print(f"❌ Dashboard connection error: {e}")

if __name__ == "__main__":
    event_handler = DLPHandler()
    observer = Observer()

    print("--- Starting Multi-Path DLP Monitor ---")
    for path in WATCH_PATHS:
        # This ensures the folders exist locally so the monitor can attach to them
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
            print(f"✅ Created Directory: {path}")
        
        observer.schedule(event_handler, path, recursive=False)
        print(f"🛡️  Monitoring: {path}")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nStopping Monitor...")
    observer.join()