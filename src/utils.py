import os
import json
from datetime import datetime, timezone, timedelta

# TODO: get these paths from a config file or environment variables
SETTINGS_PATH = "data/settings.json"
DEVICE_LIST_PATH = "data/device_list.json"
SELECTED_DEVICES_PATH = "data/selected_devices.json"
TOKEN_PATH = "data/token_info.json"
DEFAULT_SETTINGS_PATH = "resources/default_settings.json"
DEFAULT_DEVICE_LIST_PATH = "resources/default_device_list.json"
DEFAULT_SELECTED_DEVICES_PATH = "resources/default_selected_devices.json"

# Method to flatten a nested dictionary into a flat dictionary
# Example: {'a': {'b': 1, 'c': 2}} -> {'a.b': 1, 'a.c': 2}
def unflatten_dict(flat_dict):
    nested = {}
    for compound_key, value in flat_dict.items():
        keys = compound_key.split('.')
        d = nested
        for key in keys[:-1]:
            d = d.setdefault(key, {})
        d[keys[-1]] = value
    return nested

# Method to save a dictionary to a JSON file
# It creates the directory if it does not exist.
def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

# Method to load settings from a JSON file
# If the file does not exist, it creates it with default values.
def load_settings():
    if not os.path.exists(SETTINGS_PATH):
        os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
        with open(SETTINGS_PATH, "w") as f:
            with open(DEFAULT_SETTINGS_PATH, "r") as default_f:
                json.dump(json.load(default_f), f, indent=4)
    with open(SETTINGS_PATH, "r") as f:
        return json.load(f)

# Method to load device list from a JSON file
# If the file does not exist, it creates it with default values.
def load_device_list():
    if not os.path.exists(DEVICE_LIST_PATH):
        os.makedirs(os.path.dirname(DEVICE_LIST_PATH), exist_ok=True)
        with open(DEVICE_LIST_PATH, "w") as f:
            with open(DEFAULT_DEVICE_LIST_PATH, "r") as default_f:
                json.dump(json.load(default_f), f, indent=4)
    with open(DEVICE_LIST_PATH, "r") as f:
        return json.load(f)

# Method to load selected devices from a JSON file
# If the file does not exist, it creates it with default values.
def load_selected_devices():
    if not os.path.exists(SELECTED_DEVICES_PATH):
        os.makedirs(os.path.dirname(SELECTED_DEVICES_PATH), exist_ok=True)
        with open(SELECTED_DEVICES_PATH, "w") as f:
            with open(DEFAULT_SELECTED_DEVICES_PATH, "r") as default_f:
                json.dump(json.load(default_f), f, indent=4)
    with open(SELECTED_DEVICES_PATH, "r") as f:
        return json.load(f)

# Method to load project credentials from settings.json
# It returns the "aitrios" section of the settings.
def load_project_credentials():
    settings = load_settings()
    return settings.get("aitrios", {})

# Method to load token information from a JSON file
# If the file does not exist, it returns None.
def load_token_info():
    if not os.path.exists(TOKEN_PATH):
        return None
    with open(TOKEN_PATH, "r") as f:
        return json.load(f)
    
# Method to return the current time in ISO 8601 format
# Example: get_current_time_iso8601() returns the current time in ISO 8601 format
# The returned string is in the format "YYYY-MM-DDTHH:MM:SS.sss"
def get_current_time_iso8601():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")

# Method to return the current time in ISO 8601 format minus a specified number of minutes
# Example: get_time_x_mins_ago(5) returns the current time minus 5 minutes in ISO 8601 format
# The returned string is in the format "YYYY-MM-DDTHH:MM:SS.sss"
def get_time_x_mins_ago(minutes):
    now = datetime.now(timezone.utc)
    past_time = now - timedelta(minutes=minutes)
    return past_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

# Method to return the lowest missing positive integer from a list
# Example: [1, 2, 3] -> 4, [3, 4, -1, 1] -> 2, [7, 8, 9, 11, 12] -> 1
# If the list is empty, it returns 1.
def get_lowest_missing_integer(int_list):
    if not int_list:
        return 1
    int_set = set(int_list)
    for i in range(1, max(int_list) + 2):
        if i not in int_set:
            return i
    return max(int_list) + 1