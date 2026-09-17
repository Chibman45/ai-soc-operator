import os

# SQLite is the single-node profile's serialization boundary. One process with
# multiple threads prevents accidental multi-process write contention.
bind = "0.0.0.0:5000"
workers = 1
threads = int(os.environ.get("AI_SOC_GUNICORN_THREADS", "4"))
worker_class = "gthread"
timeout = 120
graceful_timeout = 30
keepalive = 5
accesslog = "-"
errorlog = "-"
capture_output = True
