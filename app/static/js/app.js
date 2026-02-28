/* OWASP LLM Security Lab - Core JavaScript */

function addMessage(containerId, text, role) {
    const container = document.getElementById(containerId);
    const msg = document.createElement('div');
    msg.className = `chat-msg ${role}`;
    msg.textContent = text;
    container.appendChild(msg);
    container.scrollTop = container.scrollHeight;
}

function showFlag(elementId, flag) {
    const el = document.getElementById(elementId);
    el.innerHTML = `<div class="flag-value">FLAG CAPTURED: ${flag}</div>`;
}

function checkFlag() {
    const flag = document.getElementById('flag-input').value.trim();
    if (!flag) return;
    fetch('/api/flags/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flag: flag })
    })
        .then(r => r.json())
        .then(data => {
            const el = document.getElementById('flag-result');
            if (data.valid) {
                el.innerHTML = `<div class="success">${data.message}</div>`;
            } else {
                el.innerHTML = `<div class="warning">${data.message}</div>`;
            }
        });
}
