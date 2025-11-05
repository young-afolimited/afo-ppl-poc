# Setup for AITRIOS local http storage

This document explains how to setup local http storage for AITRIOS.

## Environment

1. Python version 3.8.10 or later

    ```bash
    $ python -V
    Python 3.8.10
    ```

2. Set virtual environment

    ```bash
    ./setup_python_venv.sh
    source .venv/bin/activate
    ```

    Confirm there is (.venv) at the prompt.

## Configuration file

Please make sure that [start_edge_app.py](../console/start_edge_app.py) specify metadata and input_tensor parameters in [configuration_http.json](../json/configuration_http.json) for using http storage.


```json
"port_settings": {
    "metadata": {
    "path": "/data/meta",
    "method": 2,
    "enabled": true,
    "endpoint": "http://192.168.50.147:8081",
    "storage_name": ""
    },
    "input_tensor": {
    "path": "/data/image",
    "method": 2,
    "enabled": true,
    "endpoint": "http://192.168.50.147:8081",
    "storage_name": ""
    }
},
```

## HTTP storage setup

1. Connect Type3 and server Linux PC on same subnet.  

2. Modify [webapp.py](./webapp.py) to match the directory specified in [start_edge_app.py](../console/start_edge_app.py).

    ```python
    @app_ins.put("/data/meta/{filename}")
    ```

    ```python
    @app_ins.put("/data/image/{filename}")
    ```

## Open port 8081

1. Open port 8081

    ```bash
    sudo iptables -A INPUT -p tcp --dport 8081 -j ACCEPT
    ```

2. Check if the 

    ```bash
    sudo iptables -L -n | grep 8081
    ```

    ```bash
    ACCEPT     6    --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8081
    ```

## Start server

- Usage:

    ```bash
    $ uvicorn http_storage.webapp:app_ins --reload --host <HOST address> --port 8081 --no-access-log
    ```

- Example:

    ```bash
    $ pwd
    /home/pi/work/aitrios-python-samples/src
    $ uvicorn http_storage.webapp:app_ins --reload --host $(hostname -I | awk '{print $1}') --port 8081 --no-access-log
    ```
