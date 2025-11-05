function saveProjectSettings() {
    const modal = showStatusModal('Saving settings...');

    const data = {
        'aitrios.portal_endpoint': document.getElementById('portal_endpoint').value,
        'aitrios.console_endpoint': document.getElementById('console_endpoint').value,
        'aitrios.client_id': document.getElementById('client_id').value,
        'aitrios.client_secret': document.getElementById('client_secret').value,
        'email.sender_email': document.getElementById('sender_email').value,
        'email.receiver_email': document.getElementById('receiver_email').value,
        'email.azure_connection_string': document.getElementById('azure_connection_string').value,
        'inactivity_timer': document.getElementById('inactivity_timer').value
    };

    fetch('/save_settings', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify(data)
    })
    .then(res => res.json().then(body => ({ status: res.status, body })))
    .then(({ status, body }) => {
        const resultMsg = body.message || (status === 200 ? "Settings saved." : "Unknown error");
        document.getElementById('statusMessage').innerHTML = `
            <div class="mb-2 ${body.success ? 'text-success' : 'text-danger'}">
                <strong>${resultMsg}</strong>
            </div>
        `;
        if (body.success) {
            setTimeout(() => {
                blurFocusedElement();
                modal.hide();
                location.href = '/';
            }, 1500);
        }
    })
    .catch(err => {
        console.error(err);
        document.getElementById('statusMessage').innerHTML = `
            <div class="text-danger">Error saving settings!</div>
        `;
    });
}

// Open a file input dialog to load the config file
// Check for the necessary key values and formats of the file:
// Sample: {
//     "aitrios": {
//         "portal_endpoint": "",
//         "console_endpoint": "",
//         "client_id": "",
//         "client_secret": ""
//     },
//     "email": {
//         "sender_email": "",
//         "receiver_email": "",
//         "azure_connection_string": ""
//     },
//     "inactivity_timer": "5"
// }
// after loading, save the settings using the saveProjectSettings function
// Validate the structure of the config data
function validateConfigData(data) {
    if (
        typeof data !== 'object' || data === null ||
        typeof data.aitrios !== 'object' || data.aitrios === null ||
        typeof data.email !== 'object' || data.email === null
    ) {
        return false;
    }
    const aitriosKeys = ['portal_endpoint', 'console_endpoint', 'client_id', 'client_secret'];
    const emailKeys = ['sender_email', 'receiver_email', 'azure_connection_string'];
    for (const key of aitriosKeys) {
        if (typeof data.aitrios[key] !== 'string') return false;
    }
    for (const key of emailKeys) {
        if (typeof data.email[key] !== 'string') return false;
    }
    if (typeof data.inactivity_timer !== 'string' && typeof data.inactivity_timer !== 'number') {
        return false;
    }
    return true;
}

function loadConfigFile() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = e => {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = event => {
            try {
                const data = JSON.parse(event.target.result);
                if (validateConfigData(data)) {
                    document.getElementById('portal_endpoint').value = data['aitrios']['portal_endpoint'] || '';
                    document.getElementById('console_endpoint').value = data['aitrios']['console_endpoint'] || '';
                    document.getElementById('client_id').value = data['aitrios']['client_id'] || '';
                    document.getElementById('client_secret').value = data['aitrios']['client_secret'] || '';
                    document.getElementById('sender_email').value = data['email']['sender_email'] || '';
                    document.getElementById('receiver_email').value = data['email']['receiver_email'] || '';
                    document.getElementById('azure_connection_string').value = data['email']['azure_connection_string'] || '';
                    document.getElementById('inactivity_timer').value = data['inactivity_timer'] || '';
                } else {
                    alert("Invalid config file format.");
                }
            } catch (err) {
                console.error("Error parsing config file:", err);
                alert("Failed to load config file. Please ensure it is a valid JSON.");
            }
        };
        reader.readAsText(file);
    };
    input.click();
}