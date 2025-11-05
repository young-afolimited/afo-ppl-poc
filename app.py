from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file
from PIL import Image
import io
import json
import base64
from datetime import datetime, timedelta
from src.azure_email import EmailService
from settings_loader import load_settings
settings = load_settings()

from src.utils import (
    SETTINGS_PATH, SELECTED_DEVICES_PATH, DEVICE_LIST_PATH, TOKEN_PATH,
    load_settings, load_selected_devices, save_json, unflatten_dict
)

from src.console_wrapper import (
    get_device, get_devices, get_latest_person_detection, send_sample_command_direct_get_image,
    start_application_process, stop_application_process, is_device_application_process_running
)

app = Flask(__name__)
app.config['PORT'] = 8080

def init_email_service():
    # load the email credentials
    settings = load_settings()
    email_settings = settings.get("email", {})
    azure_connection_string = email_settings.get("azure_connection_string")
    sender_email = email_settings.get("sender_email")
    if not azure_connection_string or not sender_email:
        raise ValueError("Email connection string and sender email must be set in settings.")
    return EmailService(azure_connection_string, sender_email)

def update_device_notification(device_id, new_notification):
    devices = load_selected_devices()
    if device_id not in devices:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": False, "message": f"Device '{device_id}' not found."}), 404
        return redirect(url_for('index', tab='devices'))

    devices[device_id]['notifications'] = new_notification
    save_json(SELECTED_DEVICES_PATH, devices)

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            "success": True,
            "message": f"Device '{device_id}' notifications successfully set to '{new_notification}'.",
            "notifications": new_notification
        })
    return redirect(url_for('index', tab='devices'))

def update_device_status(new_status):
    device_id = request.form.get("device_id")
    devices = load_selected_devices()
    if device_id not in devices:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": False, "message": f"Device '{device_id}' not found."}), 404
        return redirect(url_for('index', tab='devices'))

    devices[device_id]['status'] = new_status
    save_json(SELECTED_DEVICES_PATH, devices)

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            "success": True,
            "message": f"Device '{device_id}' successfully set to '{new_status}'.",
            "status": new_status
        })
    return redirect(url_for('index', tab='devices'))

global email_initialized
email_initialized = False
try:
    EmailService = init_email_service()
    email_initialized = True
except ValueError as e:
    print(f"Error initializing EmailService: {e}")
    email_initialized = False

@app.route('/.well-known/appspecific/com.chrome.devtools.json')
def devtools_probe():
    return {}, 204

@app.route('/')
def index():
    settings = load_settings()
    devices = load_selected_devices()
    active_tab = request.args.get("tab", "devices")
    return render_template('index.html', settings=settings, devices=devices, tab=active_tab)

@app.route('/save_settings', methods=['POST'])
def save_settings_route():
    flat_data = request.get_json() if request.is_json else request.form.to_dict()    
    nested_data = unflatten_dict(flat_data)
    save_json(SETTINGS_PATH, nested_data)
    return jsonify({"success": True, "message": "Settings saved successfully."})

@app.route('/poll_device_status', methods=['POST'])
def poll_device_status():
    # Step 1: Refresh device list (reuse the same logic from refresh_console_devices)
    response = get_devices()
    devices = response.get("devices", [])

    device_map = {
        device.get("device_id"): {
            "device_name": device.get("device_name", "Unnamed"),
            "connection_state": device.get("connection_state", "Unknown"),
            "device_group": device.get("device_groups", [{}])[0].get("device_group_id", "No Group")
        }
        for device in devices if "device_id" in device
    }

    save_json(DEVICE_LIST_PATH, device_map)

    # Step 2: Update connection status in selected devices
    selected_devices = load_selected_devices()
    connected_devices = []

    for device_id, info in selected_devices.items():
        if device_id in device_map:
            connection_state = device_map[device_id].get("connection_state", "Unknown")
            info["connection_state"] = connection_state

            # Optional: update "last_polled" if connected
            if connection_state.lower() == "connected":
                info["last_polled"] = datetime.utcnow().isoformat()
                connected_devices.append(device_id)

                last_person_detection = get_latest_person_detection(device_id, 30, 0.4)
                print(f"Last person detection for {device_id}: {last_person_detection}")
                info["last_person_detected"] = last_person_detection

    save_json(SELECTED_DEVICES_PATH, selected_devices)

    # read the selected device again:
    selected_devices = load_selected_devices()
    connected_devices = [
        {
            "device_id": device_id,
            "device_name": selected_devices[device_id]["device_name"],
            "connection_state": selected_devices[device_id]["connection_state"],
            "last_polled": selected_devices[device_id].get("last_polled", "N/A"),
            "last_person_detected": selected_devices[device_id].get("last_person_detected", "N/A"),
            "notifications": selected_devices[device_id].get("notifications", "disabled"),
            "device_group": selected_devices[device_id].get("device_group", "No Group")
        }
        for device_id in connected_devices
    ]
    print(f"Connected devices: {connected_devices}")

    # update email settings
    email_settings = load_settings().get("email", {})
    try:
        EmailService.update_connection_string(email_settings.get("azure_connection_string"))
    except ValueError as e:
        print(f"Error updating email connection string: {e}")
        return jsonify({"success": False, "message": "Email connection string is not set."}), 400

    try:
        EmailService.update_sender_address(email_settings.get("sender_email"))
    except ValueError as e:
        print(f"Error updating email sender address: {e}")
        return jsonify({"success": False, "message": "Email sender address is not set."}), 400
    
    inactivity_timer = load_settings().get("inactivity_timer")
    print(f"Inactivity timer set to: {inactivity_timer} minutes")

    # Group devices by device_group for group-based inactivity notification
    from collections import defaultdict
    group_map = defaultdict(list)
    for device in connected_devices:
        # Use 'device_group' if available, else fallback to 'No Group'
        group_id = selected_devices[device["device_id"]].get("device_group", "No Group")
        group_map[group_id].append(device)

    now_dt = datetime.utcnow()
    inactivity_threshold = timedelta(minutes=int(inactivity_timer))
    for group_id, group_devices in group_map.items():
        # Only consider devices with notifications enabled
        enabled_devices = [d for d in group_devices if d["notifications"] == "enabled"]
        if not enabled_devices:
            continue  # No notifications enabled in this group

        # Check if any device in the group has detected a person within the inactivity period
        any_recent_detection = False
        for device in enabled_devices:
            last_person_detected = device["last_person_detected"]
            if last_person_detected and last_person_detected != "N/A":
                try:
                    last_person_dt = datetime.fromisoformat(last_person_detected)
                    if now_dt - last_person_dt <= inactivity_threshold:
                        any_recent_detection = True
                        break
                except Exception as e:
                    print(f"Error parsing last_person_detected for device {device['device_id']}: {e}")

        if not any_recent_detection:
            # No device in the group has detected a person recently, send a group email
            print(f"No recent detection in group {group_id}, sending group inactivity email.")
            # Compose group info for the email
            group_info = {
                "group_id": group_id,
                "devices": [
                    {
                        "device_id": d["device_id"],
                        "device_name": d["device_name"],
                        "last_person_detected": d["last_person_detected"]
                    } for d in enabled_devices
                ]
            }
            poller = EmailService.send_inactivity_notification(
                recipient_address=email_settings.get("receiver_email"),
                inactivity_timer=inactivity_timer,
                device=group_info  # Pass group info instead of single device
            )
            result = EmailService.poll_email_status(poller, wait_time=10, timeout=60)
            print(f"Group email sent for group {group_id}: {result}")
            if result["status"] == "Succeeded":
                print(f"Group email sent successfully for group {group_id}")
                # Disable notifications for all devices in this group
                for d in enabled_devices:
                    selected_devices[d["device_id"]]["notifications"] = "disabled"

    save_json(SELECTED_DEVICES_PATH, selected_devices)

    return jsonify({
        "success": True,
        "message": f"{len(connected_devices)} connected devices updated.",
        "connected_devices": connected_devices
    })


@app.route('/poll_device_status_old', methods=['POST'])
def poll_device_status_old():
    # Step 1: Refresh device list (reuse the same logic from refresh_console_devices)
    response = get_devices()
    devices = response.get("devices", [])

    device_map = {
        device.get("device_id"): {
            "device_name": device.get("device_name", "Unnamed"),
            "connection_state": device.get("connection_state", "Unknown")
        }
        for device in devices if "device_id" in device
    }

    save_json(DEVICE_LIST_PATH, device_map)

    # Step 2: Update connection status in selected devices
    selected_devices = load_selected_devices()
    connected_devices = []

    for device_id, info in selected_devices.items():
        if device_id in device_map:
            connection_state = device_map[device_id].get("connection_state", "Unknown")
            info["connection_state"] = connection_state

            # Optional: update "last_polled" if connected
            if connection_state.lower() == "connected":
                info["last_polled"] = datetime.utcnow().isoformat()
                connected_devices.append(device_id)

                last_person_detection = get_latest_person_detection(device_id, 30, 0.4)
                print(f"Last person detection for {device_id}: {last_person_detection}")
                info["last_person_detected"] = last_person_detection

    save_json(SELECTED_DEVICES_PATH, selected_devices)

    # read the selected device again:
    selected_devices = load_selected_devices()
    connected_devices = [
        {
            "device_id": device_id,
            "device_name": selected_devices[device_id]["device_name"],
            "connection_state": selected_devices[device_id]["connection_state"],
            "last_polled": selected_devices[device_id].get("last_polled", "N/A"),
            "last_person_detected": selected_devices[device_id].get("last_person_detected", "N/A"),
            "notifications": selected_devices[device_id].get("notifications", "disabled")
        }
        for device_id in connected_devices
    ]
    print(f"Connected devices: {connected_devices}")

    # update email settings
    email_settings = load_settings().get("email", {})
    try:
        EmailService.update_connection_string(email_settings.get("azure_connection_string"))
    except ValueError as e:
        print(f"Error updating email connection string: {e}")
        return jsonify({"success": False, "message": "Email connection string is not set."}), 400

    try:
        EmailService.update_sender_address(email_settings.get("sender_email"))
    except ValueError as e:
        print(f"Error updating email sender address: {e}")
        return jsonify({"success": False, "message": "Email sender address is not set."}), 400
    
    inactivity_timer = load_settings().get("inactivity_timer")
    print(f"Inactivity timer set to: {inactivity_timer} minutes")

    # for each connected device, check the last person detected field
    # sample output of last person detected: 2025-07-02T23:31:54.08
    # now check for each device if the last person detected is within the inactivity timer
    for device in connected_devices:
        last_person_detected = device["last_person_detected"]
        print(f"Last person detected for device {device['device_id']}: {last_person_detected}")
        notification_enabled = device["notifications"] == "enabled"
        print(f"Notification enabled for device {device['device_id']}: {notification_enabled}")
        if not last_person_detected and notification_enabled:
            print(f"No person detected for device {device['device_id']}, skipping email notification.")
            # email
            poller = EmailService.send_inactivity_notification(
                recipient_address=email_settings.get("receiver_email"),
                inactivity_timer=inactivity_timer,
                device=device
            )
            result = EmailService.poll_email_status(poller, wait_time=10, timeout=60)
            print(f"Email sent for device {device['device_id']}: {result}")
            if result["status"] == "Succeeded":
                print(f"Email sent successfully for device {device['device_id']}")
                # set the notifications to disabled for this device
                selected_devices[device["device_id"]]["notifications"] = "disabled"
        if last_person_detected and notification_enabled:
            last_person_dt = datetime.fromisoformat(last_person_detected)
            now_dt = datetime.utcnow()
            # Ensure inactivity_timer is an int for timedelta
            inactivity_threshold = timedelta(minutes=int(inactivity_timer))
            print("Inactivity threshold: ", inactivity_threshold)
            # if the last person detected is older than inactivity time, send an email notification
            if now_dt - last_person_dt > inactivity_threshold:
                poller = EmailService.send_inactivity_notification(
                    recipient_address=email_settings.get("receiver_email"),
                    inactivity_timer=inactivity_timer,
                    device=device
                )
                result = EmailService.poll_email_status(poller, wait_time=10, timeout=60)
                print(f"Email sent for device {device['device_id']}: {result}")
                if result["status"] == "Succeeded":
                    print(f"Email sent successfully for device {device['device_id']}")
                    # set the notifications to disabled for this device
                    selected_devices[device["device_id"]]["notifications"] = "disabled"

    save_json(SELECTED_DEVICES_PATH, selected_devices)

    return jsonify({
        "success": True,
        "message": f"{len(connected_devices)} connected devices updated.",
        "connected_devices": connected_devices
    })


@app.route('/refresh_console_devices', methods=['GET'])
def refresh_console_devices():
    response = get_devices()
    print(f"Response from get_devices: {response}")
    devices = response.get("devices", [])

    device_map = {
        device.get("device_id"): {
            "device_name": device.get("device_name", "Unnamed"),
            "connection_state": device.get("connection_state", "Unknown"),
            "device_group": device.get("device_groups", [{}])[0].get("device_group_id", "No Group")
        }
        for device in devices if "device_id" in device
    }
    from src.utils import save_json, DEVICE_LIST_PATH
    save_json(DEVICE_LIST_PATH, device_map)
      # Now update connection status in selected_devices
    selected_devices = load_selected_devices()

    for device_id, selected_info in selected_devices.items():
        if device_id in device_map:
            selected_info['connection_state'] = device_map[device_id].get('connection_state', 'Unknown')

    save_json(SELECTED_DEVICES_PATH, selected_devices)

    return jsonify({
        "success": True,
        "devices": device_map
    })

@app.route('/get_cached_device_list', methods=['GET'])
def get_cached_device_list():
    from src.utils import load_device_list
    try:
        device_map = load_device_list()
        return jsonify({
            "success": True,
            "devices": device_map
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/add_device', methods=['POST'])
def add_device():
    device_id = request.form.get("device_id")
    if not device_id:
        return jsonify({"success": False, "message": "Device ID is required."}), 400

    device_result = get_device(device_id)
    parsed_device_id = device_result.get("device_id", device_id)
    device_name = device_result.get("device_name", "Unnamed Device")
    connection_state = device_result.get("connection_state", "Unknown")
    module_id = device_result.get("modules", [{}])[0].get("module_id", "Unknown Module")
    module_status = device_result.get("modules", [{}])[0].get("property", {}).get("state", {}).get("edge_app", {}).get("common_settings", {}).get("process_state")
    # device_group device['device_groups'][0]['device_group_id']
    device_group = device_result.get("device_groups", [{}])[0].get("device_group_id", "No Group")
    if module_status == 2:
        module_status = "running"
    elif module_status == 1:
        module_status = "stopped"

    devices = load_selected_devices()
    if parsed_device_id in devices:
        return jsonify({"success": False, "message": f"Device '{parsed_device_id}' already exists."}), 400

    # TODO: check for status of the device rather than defaulting to "stopped"
    devices[parsed_device_id] = {
        "device_name": device_name,
        "status": module_status,
        "last_polled": "N/A",
        "last_person_detected": "N/A",
        "connection_state": connection_state,
        "notifications": "disabled",
        "module_id": module_id, 
        "device_group": device_group
    }

    save_json(SELECTED_DEVICES_PATH, devices)

    return jsonify({
        "success": True,
        "message": f"Device '{parsed_device_id}' added successfully.",
        "device": devices[parsed_device_id]
    })

@app.route('/start_device', methods=['POST'])
def start_device():
    device_id = request.form.get("device_id")
    if not device_id:
        return jsonify({"success": False, "message": "Device ID is required."}), 400
    # from selected devices, get the module_id for the device
    devices = load_selected_devices()
    if device_id not in devices:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": False, "message": f"Device '{device_id}' not found."}), 404
        return redirect(url_for('index', tab='devices'))
    module_id = devices[device_id].get("module_id")
    if not module_id:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": False, "message": f"Module ID for device '{device_id}' not found."}), 404
        return redirect(url_for('index', tab='devices'))
    # Start the application process for the device
    result = start_application_process(device_id, module_id)
    # check for success in the result
    # sample response {'result': 'SUCCESS'}
    if result.get("result") != "SUCCESS":
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": False, "message": f"Failed to start device '{device_id}': {result.get('message', 'Unknown error')}"})
        return redirect(url_for('index', tab='devices'))
    # make sure the device is actually running
    if not is_device_application_process_running(device_id, module_id):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": False, "message": f"Device '{device_id}' is not running after start command."}), 500
        return redirect(url_for('index', tab='devices'))
    # Update the device status in selected devices
    devices[device_id]['status'] = 'running'
    # save the updated devices
    save_json(SELECTED_DEVICES_PATH, devices)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            "success": True,
            "message": f"Device '{device_id}' started successfully.",
            "status": devices[device_id]['status']
        })

@app.route('/stop_device', methods=['POST'])
def stop_device():
    device_id = request.form.get("device_id")
    if not device_id:
        return jsonify({"success": False, "message": "Device ID is required."}), 400
    # from selected devices, get the module_id for the device
    devices = load_selected_devices()
    if device_id not in devices:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": False, "message": f"Device '{device_id}' not found."}), 404
        return redirect(url_for('index', tab='devices'))
    module_id = devices[device_id].get("module_id")
    if not module_id:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": False, "message": f"Module ID for device '{device_id}' not found."}), 404
        return redirect(url_for('index', tab='devices'))
    # Stop the application process for the device
    result = stop_application_process(device_id, module_id)
    # check for success in the result
    # sample response {'result': 'SUCCESS'}
    if result.get("result") != "SUCCESS":
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": False, "message": f"Failed to stop device '{device_id}': {result.get('message', 'Unknown error')}"})
        return redirect(url_for('index', tab='devices'))
    # make sure the device is actually stopped
    if is_device_application_process_running(device_id, module_id):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": False, "message": f"Device '{device_id}' is still running after stop command."}), 500
        return redirect(url_for('index', tab='devices'))
    # Update the device status in selected devices
    devices[device_id]['status'] = 'stopped'
    # save the updated devices
    save_json(SELECTED_DEVICES_PATH, devices)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            "success": True,
            "message": f"Device '{device_id}' stopped successfully.",
            "status": devices[device_id]['status']
        })

@app.route('/delete_device', methods=['POST'])
def delete_device():
    device_id = request.form.get("device_id")
    devices = load_selected_devices()
    if device_id in devices:
        del devices[device_id]
        save_json(SELECTED_DEVICES_PATH, devices)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"success": True, "message": f"Device '{device_id}' deleted."})
    return redirect(url_for('index', tab='devices'))

# Dummy endpoint, not currently used or incorporated into the UI
@app.route('/get_device_info')
def get_device_info():
    device_id = request.args.get("device_id")
    # from selected devices, get the device info and return it
    devices = load_selected_devices()
    if device_id not in devices:
        return jsonify({"success": False, "message": f"Device '{device_id}' not found."}), 404
    device_info = devices[device_id]
    # add the device_id to the device_info
    device_info['device_id'] = device_id
    # return the device info as JSON
    return jsonify({"success": True, "device_info": device_info})

# Dummy endpoint, not currently used or incorporated into the UI
@app.route('/set_device_info', methods=['POST'])
def set_device_info():
    device_id = request.form.get("device_id")
    device_name = request.form.get("device_name")
    devices = load_selected_devices()
    if device_id not in devices:
        return jsonify({"success": False, "message": f"Device '{device_id}' not found."}), 404
    if not device_name:
        return jsonify({"success": False, "message": "Device name is required."}), 400
    # Update the device name
    devices[device_id]['device_name'] = device_name
    save_json(SELECTED_DEVICES_PATH, devices)
    return jsonify({"success": True, "message": f"Device '{device_id}' updated successfully."})

@app.route('/enable_notifications', methods=['POST'])
def enable_notifications():
    device_id = request.form.get("device_id")
    return update_device_notification(device_id, 'enabled')

@app.route('/disable_notifications', methods=['POST'])
def disable_notifications():
    device_id = request.form.get("device_id")
    return update_device_notification(device_id, 'disabled')

@app.route('/get_preview')
def get_preview():
    device_id = request.args.get("device_id")
    if not device_id:
        return jsonify({"success": False, "message": "Device ID is required."}), 400

    # Get the latest image from the device
    response = send_sample_command_direct_get_image(device_id)
    if response.get("result") != "SUCCESS":
        return jsonify({"success": False, "message": f"Failed to get preview for device '{device_id}': {response.get('message', 'Unknown error')}"})

    # Decode the base64 image
    image_data = response.get("command_response", {}).get("image", "")
    if not image_data:
        return jsonify({"success": False, "message": "No image data found."}), 404

    try:
        image_bytes = base64.b64decode(image_data)
        image = Image.open(io.BytesIO(image_bytes))
        img_io = io.BytesIO()
        image.save(img_io, format='JPEG')
        img_io.seek(0)
        return send_file(img_io, mimetype='image/jpeg')
    except Exception as e:
        return jsonify({"success": False, "message": f"Error processing image: {str(e)}"}), 500

@app.route('/get_selected_devices', methods=['GET'])
def get_selected_devices():
    devices = load_selected_devices()
    return jsonify({"success": True, "devices": devices})

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)