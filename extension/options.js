document.getElementById('save').addEventListener('click', () => {
  const apiKey = document.getElementById('apiKey').value;
  chrome.storage.local.set({ vtApiKey: apiKey }, () => {
    const status = document.getElementById('status');
    status.style.display = 'block';
    setTimeout(() => { status.style.display = 'none'; }, 2000);
  });
});

// Charger la clé existante
chrome.storage.local.get('vtApiKey', (data) => {
  if (data.vtApiKey) {
    document.getElementById('apiKey').value = data.vtApiKey;
  }
});
