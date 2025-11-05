import os
import json
import base64
import datetime
import requests

from src.object_detection.object_detection import decode_object_detection

from src.utils import (
    TOKEN_PATH, SETTINGS_PATH, SELECTED_DEVICES_PATH, DEVICE_LIST_PATH,
    load_project_credentials, load_token_info, save_json, get_current_time_iso8601, get_time_x_mins_ago
)

# hardcode the module id for now
# TODO: find best way to find module id
MODULE_ID = "b8d57d00-ba85-4fd0-b78a-4908bde744a5"

def get_token(portal_endpoint, authorization):
    # Get token
    headers = {
        'accept': 'application/json',
        'authorization': 'Basic {}'.format(str(authorization)),
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded'
    }
    data = 'grant_type=client_credentials&scope=system'
    response = requests.post(portal_endpoint, headers=headers, data=data)
    print("Response Status Code: ", response.status_code)
    json_data = response.json()
    token = str(json_data['access_token'])
    # Save token to JSON file
    now_dt = datetime.datetime.now().isoformat()
    token_info = {'datetime': now_dt, 'token': token}
    # save token 
    save_json(TOKEN_PATH, token_info)
    return token

def update_token(client_id, client_secret, portal_endpoint, expiry_time= 3600):
    authorization = base64.b64encode((client_id + ':' + client_secret).encode()).decode()
    token_info = load_token_info()
    if token_info:
        token_time = datetime.datetime.fromisoformat(token_info['datetime'])
        now_dt = datetime.datetime.now()
        if (now_dt - token_time).total_seconds() > expiry_time:
            print("Token expired, fetching new token.")
            token = get_token(portal_endpoint, authorization)
        else:
            token = token_info['token']
    else:
        token = get_token(portal_endpoint, authorization)
    return token

def get_device(device_id):
    # get access token
    project_credentials = load_project_credentials()
    access_token = update_token(
        project_credentials['client_id'],
        project_credentials['client_secret'],
        project_credentials['portal_endpoint']
    )
    headers  = {'Authorization': 'Bearer {}'.format(access_token)}
    get_device_url = project_credentials["console_endpoint"] + '/devices/' + device_id
    response = requests.get(get_device_url, headers=headers)
    json_data = response.json()
    print("Get Device Response: ", json_data)
    return json_data

def get_devices():
    project_credentials = load_project_credentials()
    access_token = update_token(
        project_credentials['client_id'],
        project_credentials['client_secret'],
        project_credentials['portal_endpoint']
    )
    headers  = {'Authorization': 'Bearer {}'.format(access_token)}
    get_devices_url = project_credentials["console_endpoint"] + '/devices'
    response = requests.get(get_devices_url, headers=headers)
    json_data = response.json()
    # print("Get Devices Response: ", json_data)
    return json_data

def get_inferences(devices, limit=None, from_datetime=None, to_datetime=None):
    # get access token
    project_credentials = load_project_credentials()
    access_token = update_token(
        project_credentials['client_id'],
        project_credentials['client_secret'],
        project_credentials['portal_endpoint']
    )
    headers  = {'Authorization': 'Bearer {}'.format(access_token)}
    get_inferences_url = project_credentials["console_endpoint"] + '/inferenceresults'
    
    params = {
        'devices': devices,
    }
    if limit is not None:
        params['limit'] = limit
    if from_datetime is not None:
        params['from_datetime'] = from_datetime
    if to_datetime is not None:
        params['to_datetime'] = to_datetime
    response = requests.get(get_inferences_url, headers=headers, params=params)
    json_data = response.json()
    return json_data

def send_sample_command_direct_get_image(device_id, command_name=None, parameters=None):
    parameters = parameters or {
        "sensor_name": "IMX500",
        "crop_h_offset": 0,
        "crop_v_offset": 0,
        "crop_h_size": 2028,
        "crop_v_size": 1520
    }
    project_credentials = load_project_credentials()
    access_token = update_token(
        project_credentials['client_id'],
        project_credentials['client_secret'],
        project_credentials['portal_endpoint']
    )
    headers = {'Authorization': 'Bearer {}'.format(access_token)}
    send_command_url = project_credentials["console_endpoint"] + '/devices/' + device_id + '/modules/$system/command'
    payload = {
        "command_name": "direct_get_image",
        "parameters": parameters
    }
    response = requests.post(send_command_url, headers=headers, json=payload)
    json_data = response.json()
    print("Send Command Response: ", json_data)
    return json_data

def is_person_detected(inference, threshold=0.5):
    """
    Checks if a person is detected in the inference object with probability above threshold.
    Returns (timestamp, presence) where presence is True/False.
    """
    timestamp = inference.get('T')
    presence = False
    for key, value in inference.items():
        if key in ('T', 'F'):
            continue
        if isinstance(value, dict):
            if value.get('C') == 'person' and value.get('P', 0) >= threshold:
                presence = True
                break
    return timestamp, presence

# method to get latest x minutes of inference data and return timestamp of last person detected in that time
# min minutes = 1, max = 60
def get_latest_person_detection(devices, minutes=15, threshold=0.5):
    if minutes < 1 or minutes > 60:
        raise ValueError("Minutes must be between 1 and 60")
    
    to_datetime = get_current_time_iso8601()
    from_datetime = get_time_x_mins_ago(minutes)
    
    inferences = get_inferences(
        devices=devices,
        from_datetime=from_datetime,
        to_datetime=to_datetime
    )
    
    for inference in inferences['inferences']:
        out = decode_object_detection(
            json_data=inference,
            label_file='src/object_detection/class_definition_file/class80.txt'
        )
        if out[1] == False:
            continue
        timestamp, presence = is_person_detected(out[1], threshold)
        if presence:
            return timestamp
    return None

# endpoint path is /devices/<device_id>/property
def get_device_property(device_id):
    project_credentials = load_project_credentials()
    access_token = update_token(
        project_credentials['client_id'],
        project_credentials['client_secret'],
        project_credentials['portal_endpoint']
    )
    headers = {'Authorization': 'Bearer {}'.format(access_token)}
    get_property_url = project_credentials["console_endpoint"] + '/devices/' + device_id + '/property'
    response = requests.get(get_property_url, headers=headers)
    json_data = response.json()
    print("Get Device Property Response: ", json_data)
    return json_data

# endpoint path is /devices/<device_id>/modules/<module_id>
def get_property(device_id, module_id):
    project_credentials = load_project_credentials()
    access_token = update_token(
        project_credentials['client_id'],
        project_credentials['client_secret'],
        project_credentials['portal_endpoint']
    )
    headers = {'Authorization': 'Bearer {}'.format(access_token)}
    get_property_url = project_credentials["console_endpoint"] + '/devices/' + device_id + '/modules/' + module_id
    response = requests.get(get_property_url, headers=headers)
    json_data = response.json()
    return json_data

# endpoint path is /devices/<device_id>/modules/<module_id>/property
def get_module_property(device_id, module_id):
    project_credentials = load_project_credentials()
    access_token = update_token(
        project_credentials['client_id'],
        project_credentials['client_secret'],
        project_credentials['portal_endpoint']
    )
    headers = {'Authorization': 'Bearer {}'.format(access_token)}
    get_property_url = project_credentials["console_endpoint"] + '/devices/' + device_id + '/modules/' + module_id + '/property'
    response = requests.get(get_property_url, headers=headers)
    json_data = response.json()
    return json_data

def update_module_property(device_id, module_id, module_config=None):
    project_credentials = load_project_credentials()
    access_token = update_token(
        project_credentials['client_id'],
        project_credentials['client_secret'],
        project_credentials['portal_endpoint']
    )
    headers = {'Authorization': 'Bearer {}'.format(access_token), 'Content-Type': 'application/json'}
    # Prepare the payload
    payload = {
        "configuration": module_config
    }
    update_property_url = project_credentials["console_endpoint"] + '/devices/' + device_id + '/modules/' + module_id + '/property'
    response = requests.patch(update_property_url, headers=headers, json=payload)
    if response.status_code == 200:
        return response.json()
    else:
        print("Failed to update module property. Status code:", response.status_code)
        return None

def generate_device_image_path(device_id):
    """
    Generates a device image path based on the device ID.
    The path is structured as: <device_id>/images/<timestamp>.jpg
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    return f"{device_id}/image/{timestamp}"

def start_application_process(device_id, module_id):
    """
    Starts the application process for a specific module on a device.
    """
    # get the module property
    current_module_property = get_module_property(device_id, module_id)
    configuration = current_module_property.get('configuration', {})
    if not configuration:
        print("No configuration found for the module.")
        return None
    configuration['edge_app']['common_settings']['process_state'] = 2
    # configuration["edge_app"]["common_settings"]["port_settings"]["metadata"]["path"] = ""
    configuration["edge_app"]["common_settings"]["port_settings"]["input_tensor"]["path"] = generate_device_image_path(device_id)

    print("configuration: ", json.dumps(configuration, indent=2))
    # update the module property with the new configuration
    update_result = update_module_property(
        device_id=device_id,
        module_id=module_id,
        module_config=configuration
    )
    if update_result:
        return update_result
    else:
        print("Failed to start module process.")
        return None
    
def stop_application_process(device_id, module_id):
    """
    Stops the application process for a specific module on a device.
    """
    # get the module property
    current_module_property = get_module_property(device_id, module_id)
    configuration = current_module_property.get('configuration', {})
    if not configuration:
        print("No configuration found for the module.")
        return None
    configuration['edge_app']['common_settings']['process_state'] = 1
    # update the module property with the new configuration
    update_result = update_module_property(
        device_id=device_id,
        module_id=module_id,
        module_config=configuration
    )
    if update_result:
        print("Module process stopped successfully.")
        return update_result
    else:
        print("Failed to stop module process.")
        return None
    
def get_current_device_application_process_state(device_id, module_id):
    """
    Gets the current application process state for a specific module on a device.
    """
    # get the module property
    current_module_property = get_module_property(device_id, module_id)
    configuration = current_module_property.get('configuration', {})
    if not configuration:
        print("No configuration found for the module.")
        return None
    process_state = configuration['edge_app']['common_settings']['process_state']
    if process_state == 1:
        print("Module process is stopped.")
    elif process_state == 2:
        print("Module process is running.")
    else:
        print("Module process state is unknown.")
    return process_state

def is_device_application_process_running(device_id, module_id):
    """
    Checks if the application process for a specific module on a device is running.
    Returns True if running, False otherwise.
    """
    process_state = get_current_device_application_process_state(device_id, module_id)
    return process_state == 2

if __name__ == '__main__':
    device_id = "Aid-80010003-0000-2000-9002-00000000026b"
    module_id = "b8d57d00-ba85-4fd0-b78a-4908bde744a5"