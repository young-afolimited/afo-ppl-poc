from azure.communication.email import EmailClient

POLLER_WAIT_TIME = 10

class EmailService:
    def __init__(self, connection_string, sender_address):
        self.client = EmailClient.from_connection_string(connection_string)
        self.sender_address = sender_address

    def send_inactivity_notification(self, recipient_address, inactivity_timer, device):
        # If device is a group info dict, send a group email
        if isinstance(device, dict) and "group_id" in device and "devices" in device:
            group_id = device["group_id"]
            devices = device["devices"]
            subject = f"Group Inactivity Alert: Group {group_id}"
            device_list = "\n".join([
                f"- {d['device_name']} (ID: {d['device_id']}), Last detected: {d.get('last_person_detected', 'N/A')}"
                for d in devices
            ])
            plain_text_body = (
                f"No person detected by any device in group '{group_id}' for more than {inactivity_timer} minutes.\n\n"
                f"Devices in this group:\n{device_list}"
            )
            html_device_list = "".join([
                f"<li>{d['device_name']} (ID: {d['device_id']}), Last detected: {d.get('last_person_detected', 'N/A')}</li>"
                for d in devices
            ])
            html_body = (
                f"<html><h1>Group '{group_id}' Inactivity Alert</h1>"
                f"<p>No person detected by any device in this group for more than {inactivity_timer} minutes.</p>"
                f"<ul>{html_device_list}</ul></html>"
            )
            return self.send_email(recipient_address, subject, plain_text_body, html_body)
        # Otherwise, treat as single device
        subject = f"Device Inactivity Alert: {device['device_name']}"
        plain_text_body = f"Device '{device['device_name']}' has been inactive for more than {inactivity_timer} minutes."
        html_body = f"<html><h1>Device '{device['device_name']}' Inactivity Alert</h1><p>Device has been inactive for more than {inactivity_timer} minutes.</p></html>"
        return self.send_email(recipient_address, subject, plain_text_body, html_body)

    def send_email(self, recipient_address, subject, plain_text_body, html_body):
        # check if all required parameters are provided
        if not recipient_address or not subject or not plain_text_body or not html_body:
            raise ValueError("All parameters must be provided to send an email.")
        message = {
            "senderAddress": self.sender_address,
            "recipients": {
                "to": [{"address": recipient_address}],
            },
            "content": {
                "subject": subject,
                "plainText": plain_text_body,
                "html": html_body,
            }
        }
        #before sending also make sure the current sender address and connection strings are not empty or None
        if not self.sender_address or not self.client:
            raise ValueError("Sender address and connection string must be set before sending an email.")
        return self.client.begin_send(message)
    
    def poll_email_status(self, poller, wait_time=10, timeout=180):
        time_elapsed = 0
        while not poller.done():
            print("Email send poller status: " + poller.status())
            poller.wait(wait_time)
            time_elapsed += wait_time

            if time_elapsed > timeout:
                raise RuntimeError("Polling timed out.")

        result = poller.result()
        if result["status"] == "Succeeded":
            print(f"Successfully sent the email (operation id: {result['id']})")
        else:
            print(f"Failed to send the email (operation id: {result['id']})")
            raise RuntimeError(str(result["error"]))
        return result
    
    def update_sender_address(self, new_sender_address):
        if not new_sender_address:
            raise ValueError("New sender address must not be empty.")
        self.sender_address = new_sender_address
        print(f"Sender address updated to: {self.sender_address}")

    def update_connection_string(self, new_connection_string):
        if not new_connection_string:
            raise ValueError("New connection string must not be empty.")
        self.client = EmailClient.from_connection_string(new_connection_string)
        print("Connection string updated successfully.")