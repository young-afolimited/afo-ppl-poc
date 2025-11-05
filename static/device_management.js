document.getElementById('previewModal').addEventListener('hidden.bs.modal', stopPreview);

document.addEventListener('DOMContentLoaded', function () {
    populateDeviceDropdown();
    fetchDevices();
});

// Fetch and render the device list
function fetchDevices() {
  fetch('/get_selected_devices')
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        renderDeviceTable(data.devices);
      }
    });
}

// Render the device table
function renderDeviceTable(devices) {
    const tbody = document.getElementById('device-table-body');  
    tbody.innerHTML = '';
    Object.entries(devices).forEach(([id, device]) => {
    const row = document.createElement('tr');
    row.id = `device-${id}`;
    inference_status = device.status
    notifications_enabled = device.notifications
    row.innerHTML = `
        <td>${device.device_group}</td>
        <td>${device.device_name}</td>
        <td>${id}</td>
        <td>${device.connection_state || ''}</td>
        <td>${device.last_polled || ''}</td>
        <td>${device.last_person_detected || ''}</td>
    `;
    if (inference_status === 'running') {
        row.innerHTML += `<td><button class="btn btn-danger" onclick="toggleInference('${id}', 'stop')">Stop </button></td>`;
    } else {
        row.innerHTML += `<td><button class="btn btn-primary" onclick="toggleInference('${id}', 'start')">Start </button></td>`;
    }
    if (notifications_enabled == "enabled") {
        row.innerHTML += `<td><button class="btn btn-warning" onclick="toggleNotifications('${id}', 'disable')">Disable </button></td>`;
    } else {
        row.innerHTML += `<td><button class="btn btn-success" onclick="toggleNotifications('${id}', 'enable')">Enable </button></td>`;
    }
    // drop down menu for options
    // add a button with three dots that opens a dropdown menu with options: Preview, Configure, Delete
    row.innerHTML += `
        <td>
            <div class="dropdown">
                <button class="btn btn-secondary dropdown-toggle" type="button" id="deviceOptionsDropdown-${id}" data-bs-toggle="dropdown" aria-expanded="false">
                    ...
                </button>
                <ul class="dropdown-menu" aria-labelledby="deviceOptionsDropdown-${id}">
                    <li><a class="dropdown-item" href="#" onclick="openPreview('${id}')">Preview</a></li>
                    <li><a class="dropdown-item" href="#" onclick="openConfigure('${id}')">Configure</a></li>
                    <li><a class="dropdown-item" href="#" onclick="confirmDelete('${id}')">Delete Device</a></li>
                </ul>
            </div>
        </td>
    `;
    tbody.appendChild(row);
  });
}

function showStatusModal(message) {
    document.getElementById('statusMessage').innerHTML = `
        <div class="spinner-border text-primary mb-2" role="status"></div>
        <div>${message}</div>
    `;
    const modal = new bootstrap.Modal(document.getElementById('statusModal'));
    modal.show();
    return modal;
}

function toggleNotifications(deviceId, action) {
    const actionLabel = action === 'enable' ? 'Enabling notifications...' : 'Disabling notifications...';
    const modal = showStatusModal(actionLabel);
    fetch(`/${action}_notifications`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: `device_id=${encodeURIComponent(deviceId)}`
    })
    .then(res => res.json().then(data => ({ status: res.status, body: data })))
    .then(({ status, body }) => {
        const resultMsg = body.message || (status === 200 ? "Success" : "Unknown error");
        document.getElementById('statusMessage').innerHTML = `

            <div class="mb-2 ${body.success ? 'text-success' : 'text-danger'}">
                <strong>${resultMsg}</strong>
            </div>
        `;
        if (body.success) {
            setTimeout(() => {
                blurFocusedElement();
                modal.hide();
                fetchDevices();
            }, 1500);
        }
    })
    .catch(err => {
        console.error(err);
        document.getElementById('statusMessage').innerHTML = `
            <div class="text-danger">Something went wrong!</div>
        `;
    });
}

function toggleInference(deviceId, action) {
    const actionLabel = action === 'start' ? 'Starting inference...' : 'Stopping device...';
    const modal = showStatusModal(actionLabel);
    fetch(`/${action}_device`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: `device_id=${encodeURIComponent(deviceId)}`
    })
    .then(res => res.json().then(data => ({ status: res.status, body: data })))
    .then(({ status, body }) => {
        const resultMsg = body.message || (status === 200 ? "Success" : "Unknown error");

        document.getElementById('statusMessage').innerHTML = `
            <div class="mb-2 ${body.success ? 'text-success' : 'text-danger'}">
                <strong>${resultMsg}</strong>
            </div>
        `;
        if (body.success) {
            setTimeout(() => {
                blurFocusedElement();
                modal.hide();
                fetchDevices();
            }, 1500);
        }
    })
    .catch(err => {
        console.error(err);
        document.getElementById('statusMessage').innerHTML = `
            <div class="text-danger">Something went wrong!</div>
        `;
    });
}

function refreshDeviceList() {
    const modal = showStatusModal('Refreshing device list...');
    fetch('/refresh_console_devices')
        .then(res => res.json())
        .then(data => {
            const dropdown = document.getElementById('newDeviceId');
            dropdown.innerHTML = `<option disabled selected>Choose a device</option>`;
            if (data.success && data.devices) {
                const entries = Object.entries(data.devices);
                for (const [id, info] of entries) {
                    const label = `${info.device_name || id} (${info.connection_state || 'Unknown'})`;
                    const option = document.createElement('option');
                    option.value = id;
                    option.textContent = label;
                    dropdown.appendChild(option);
                }

                document.getElementById('statusMessage').innerHTML = `
                    <div class="text-success mb-2"><strong>Device list refreshed successfully.</strong></div>
                `;
                setTimeout(() => {
                    blurFocusedElement();
                    modal.hide();
                    location.href = '/';
                }, 1000);
            } else {
                document.getElementById('statusMessage').innerHTML = `
                    <div class="text-danger mb-2"><strong>Failed to fetch device list.</strong></div>
                `;
            }
        })
        .catch(err => {
            console.error('Error fetching device list:', err);
            document.getElementById('statusMessage').innerHTML = `
                <div class="text-danger mb-2"><strong>Error fetching device list.</strong></div>
            `;
        });
}

function populateDeviceDropdown() {
    fetch('/get_cached_device_list')
        .then(res => res.json())
        .then(data => {
            const dropdown = document.getElementById('newDeviceId');
            dropdown.innerHTML = `<option disabled selected>Choose a device</option>`;
            if (data.success && data.devices) {
                // Convert to array and sort by device_group (ascending, undefined last)
                const sortedDevices = Object.entries(data.devices).sort((a, b) => {
                    const groupA = a[1].device_group || '';
                    const groupB = b[1].device_group || '';
                    if (groupA === groupB) return 0;
                    if (!groupA) return 1; // undefined/null/empty groups go last
                    if (!groupB) return -1;
                    return groupA.localeCompare(groupB);
                });
                sortedDevices.forEach(([id, info]) => {
                    const group = info.device_group ? `[${info.device_group}] ` : '';
                    const label = `${group}${info.device_name || id} - ${info.connection_state || 'Unknown'}`;
                    const option = document.createElement('option');
                    option.value = id;
                    option.textContent = label;
                    dropdown.appendChild(option);
                });
            } else {
                console.warn("No cached devices found.");
            }
        })
        .catch(err => {
            console.error("Failed to load cached device list", err);
        });
}

function addDevice() {
    const dropdown = document.getElementById('newDeviceId');
    const deviceID = dropdown.value.trim();
    // Prevent adding if "Choose a device" is selected (disabled/selected option)
    if (!deviceID || dropdown.selectedIndex === 0 || dropdown.options[dropdown.selectedIndex].disabled) {
        // Optionally, show a warning or shake the dropdown
        dropdown.classList.add('is-invalid');
        setTimeout(() => dropdown.classList.remove('is-invalid'), 1000);
        return;
    }
    const modal = showStatusModal('Adding device...');
    fetch('/add_device', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: `device_id=${encodeURIComponent(deviceID)}`
    })
    .then(res => res.json().then(data => ({ status: res.status, body: data })))
    .then(({ status, body }) => {
        const resultMsg = body.message || (status === 200 ? "Success" : "Unknown error");
        document.getElementById('statusMessage').innerHTML = `
            <div class="mb-2 ${body.success ? 'text-success' : 'text-danger'}">
                <strong>${resultMsg}</strong>
            </div>
        `;
        if (body.success) {
            setTimeout(() => {
                blurFocusedElement();
                modal.hide();
                fetchDevices(); // Dynamically update the table
            }, 500);
        }
    })
    .catch(err => {
        console.error(err);
        document.getElementById('statusMessage').innerHTML = `
            <div class="text-danger">Something went wrong while adding the device!</div>
        `;
    });
}

function openConfigure(deviceId) {
    fetch(`/get_device_info?device_id=${encodeURIComponent(deviceId)}`)
        .then(res => res.json())
        .then(data => {
            const formHtml = `
                <div class="mb-3">
                    <label class="form-label">Name</label>
                    <input class="form-control" value="${data.name || ''}" id="configName">
                </div>
                <!-- Add more fields dynamically if needed -->
            `;
            document.getElementById('configureFormContainer').innerHTML = formHtml;
            document.getElementById('configureModal').dataset.deviceId = deviceId;
            new bootstrap.Modal(document.getElementById('configureModal')).show();
        });
}

function submitConfiguration() {
    const modal = document.getElementById('configureModal');
    const deviceId = modal.dataset.deviceId;
    const config = {
        device_id: deviceId,
        name: document.getElementById('configName').value
    };
    fetch('/set_device_info', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
    }).then(() => {
        blurFocusedElement();
        bootstrap.Modal.getInstance(modal).hide();
    });
}

let previewInterval = null;
let previewWasRunning = false;
function openPreview(deviceId) {
    // First, check device state
    fetch(`/get_device_info?device_id=${encodeURIComponent(deviceId)}`)
        .then(res => res.json())
        .then(data => {
            // Support both {success, device_info} and flat device info
            const device = data.device_info || data;
            const wasRunning = device.status === 'running';
            previewWasRunning = wasRunning;

            // If running, stop the device first
            const maybeStop = wasRunning
                ? fetch('/stop_device', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: `device_id=${encodeURIComponent(deviceId)}`
                })
                : Promise.resolve();

            maybeStop.then(() => {
                const modal = new bootstrap.Modal(document.getElementById('previewModal'));
                modal.show();

                function fetchPreview() {
                    fetch(`/get_preview?device_id=${encodeURIComponent(deviceId)}`)
                        .then(res => {
                            if (!res.ok) throw new Error("Failed to fetch preview");
                            return res.blob();
                        })
                        .then(blob => {
                            const imgUrl = URL.createObjectURL(blob);
                            const img = document.getElementById('previewImage');
                            img.src = imgUrl;
                            // Make image responsive and fit inside modal
                            img.style.width = "100%";
                            img.style.maxWidth = "900px";
                            img.style.height = "auto";
                            img.style.display = "block";
                            img.style.margin = "0 auto";
                        })
                        .catch(() => {
                            document.getElementById('previewImage').src = '';
                        });
                }
                fetchPreview(); // Fetch immediately
                previewInterval = setInterval(fetchPreview, 2000); // Poll every 2s

                // When modal closes, clean up and restart if needed
                const previewModalEl = document.getElementById('previewModal');
                function onModalHidden() {
                    clearInterval(previewInterval);
                    previewInterval = null;
                    previewModalEl.removeEventListener('hidden.bs.modal', onModalHidden);

                    // If device was running before, start it again
                    if (previewWasRunning) {
                        fetch('/start_device', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                                'X-Requested-With': 'XMLHttpRequest'
                            },
                            body: `device_id=${encodeURIComponent(deviceId)}`
                        });
                    }
                    blurFocusedElement();
                }
                previewModalEl.addEventListener('hidden.bs.modal', onModalHidden);
            });
        });
}

function stopPreview() {
    clearInterval(previewInterval);
    blurFocusedElement();
}

function openConfirmModal(title, message, confirmCallback) {
    document.getElementById('confirmModalTitle').textContent = title;
    document.getElementById('confirmModalBody').textContent = message;
    const confirmBtn = document.getElementById('confirmActionBtn');
    const listener = () => {
        confirmCallback();
        blurFocusedElement();
        bootstrap.Modal.getInstance(document.getElementById('confirmModal')).hide();
        confirmBtn.removeEventListener('click', listener);
    };
    confirmBtn.addEventListener('click', listener);
    new bootstrap.Modal(document.getElementById('confirmModal')).show();
}

function confirmDelete(deviceId) {
    openConfirmModal("Delete Device", `Are you sure you want to delete device ${deviceId}?`, () => {
        fetch('/delete_device', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `device_id=${encodeURIComponent(deviceId)}`
        }).then(() => {
            fetchDevices();
        });
    });
}

function blurFocusedElement() {
    if (document.activeElement && typeof document.activeElement.blur === 'function') {
        document.activeElement.blur();
    }
}

function pollDeviceStatus() {
    fetch('/poll_device_status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(res => res.json())
    .then(data => {
        console.log("[Polling]", data.message);
        fetchDevices();
    })
    .catch(err => {
        console.error("Polling failed", err);
    });
}

setInterval(pollDeviceStatus, 60000);