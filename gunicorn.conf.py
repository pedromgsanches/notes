import multiprocessing

# Configurações básicas
bind = "0.0.0.0:5000"
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2
worker_class = 'sync'
worker_connections = 1000
timeout = 30
keepalive = 2

# Configurações de logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

# Configurações de processo
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None 