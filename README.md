# AFO People Presence Notification POC

## Overview

This project is a Proof of Concept (POC) web application for managing and monitoring smart camera devices, with a focus on people presence detection and automated email notifications. The application provides a user-friendly interface to:

- Register and manage smart camera devices.
- Monitor device connection status and application state.
- Detect people presence using edge AI modules.
- Automatically send email notifications via Azure Email Service when inactivity (no person detected) exceeds a configurable threshold.
- Enable or disable notifications per device.
- Preview the latest image from each device.

The system is designed for technical users and system integrators working with smart edge devices in environments such as offices, factories, or public spaces.

---

## Features

- **Device Management:** Add, remove, start, stop, and monitor smart camera devices.
- **People Presence Detection:** Integrates with edge AI modules to detect people and track last detection time.
- **Automated Email Alerts:** Sends inactivity notifications to configured recipients using Azure Email Service.
- **Web Dashboard:** Modern Flask-based web UI for device and settings management.
- **Configurable Settings:** Easily adjust email, inactivity timer, and device preferences.
- **RESTful API Endpoints:** For integration and automation.

---

## Architecture

- **Backend:** Python 3, Flask, custom modules for device and email integration.
- **Frontend:** HTML (Jinja2 templates), JavaScript, CSS.
- **Device Data:** JSON files for device lists, settings, and state.
- **Email Service:** Azure Email Service integration for sending notifications.

---

## Requirements

- Python 3.10 or higher
- pip (Python package manager)
- Azure Email Service credentials (connection string, sender email)
- Access to smart camera devices compatible with the edge AI module

### Python Dependencies

All required Python packages are listed in `requirements.txt`. Key dependencies include:

- Flask
- Pillow (PIL)
- Azure SDKs (for email)
- Other utility libraries

---

## Setup Guide

### 1. Clone the Repository

```powershell
git clone <your-repo-url>
cd afo-ppl-poc
```

### 2. Install Python Dependencies

```powershell
pip install -r requirements.txt
```

### 3. Configure Application Settings

Edit `data/settings.json` to provide your Azure Email Service credentials and other settings:

```json
{
  "email": {
    "azure_connection_string": "<your-azure-connection-string>",
    "sender_email": "<your-sender-email>",
    "receiver_email": "<recipient-email>"
  },
  "inactivity_timer": 30
}
```

- `inactivity_timer` is in minutes.

### 4. Run the Application

```powershell
python app.py
```

The web app will be available at [http://localhost:8080](http://localhost:8080).

---

## Usage Guide

### Device Management

- **Add Device:** Enter device ID to register a new device.
- **Start/Stop Device:** Control the edge AI application on each device.
- **Delete Device:** Remove a device from monitoring.
- **Enable/Disable Notifications:** Toggle inactivity email alerts per device.

### Monitoring

- **Dashboard:** View all registered devices, their connection status, last person detected, and notification state.
- **Preview:** Fetch and display the latest image from a device.

### Email Notifications

- When a device is connected and notifications are enabled, the system checks for people presence.
- If no person is detected for the configured inactivity period, an email is sent to the recipient and notifications are disabled for that device until re-enabled.

---

## REST API Endpoints

- `GET /` — Main dashboard.
- `POST /add_device` — Add a new device.
- `POST /start_device` — Start device application.
- `POST /stop_device` — Stop device application.
- `POST /delete_device` — Remove a device.
- `POST /enable_notifications` — Enable email notifications for a device.
- `POST /disable_notifications` — Disable notifications.
- `POST /poll_device_status` — Refresh device status and trigger notifications.
- `GET /get_preview` — Get latest image from a device.
- `GET /get_selected_devices` — List all registered devices.

---

## File Structure

- `app.py` — Main Flask application.
- `src/` — Core modules for device and email integration.
- `data/` — JSON files for device and settings storage.
- `static/` — Frontend JS and CSS.
- `templates/` — HTML templates for the web UI.

---

## Security & Best Practices

- Do not commit sensitive credentials to version control.
- Use strong, unique passwords for email accounts.
- Restrict access to the web application in production environments.
- Regularly update dependencies to patch security vulnerabilities.

---

## Troubleshooting

- **Email Not Sending:** Check Azure connection string and sender/receiver emails in `settings.json`.
- **Device Not Detected:** Ensure device is online and accessible.
- **Web App Not Starting:** Verify Python version and all dependencies are installed.

---

## License

This project is for demonstration and POC purposes. Please consult your organization’s policies before deploying in production.

---

## Contact

For questions or support, contact the project maintainer or open an issue in the repository.

---
