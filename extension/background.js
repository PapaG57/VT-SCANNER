// Créer l'option dans le menu contextuel
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scanLinkVT",
    title: "Analyser ce lien avec VirusTotal",
    contexts: ["link"]
  });
});

// Gérer le clic sur le menu
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scanLinkVT") {
    const url = info.linkUrl;
    scanUrl(url);
  }
});

async function scanUrl(urlToScan) {
  const data = await chrome.storage.local.get('vtApiKey');
  const apiKey = data.vtApiKey;

  if (!apiKey) {
    notify("Erreur VT-Scanner", "Veuillez configurer votre clé API dans les options de l'extension.");
    return;
  }

  // VirusTotal demande l'URL encodée en Base64 sans le padding '='
  const urlId = btoa(urlToScan).replace(/=/g, "");
  const vtUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;

  try {
    const response = await fetch(vtUrl, {
      headers: { "x-apikey": apiKey }
    });

    if (response.status === 200) {
      const result = await response.json();
      const stats = result.data.attributes.last_analysis_stats;
      const malicious = stats.malicious;

      if (malicious > 0) {
        notify("🛡️ Alerte Menace !", `Ce lien est jugé malveillant par ${malicious} moteurs.`);
      } else {
        notify("✅ Lien Sain", "Aucune menace détectée pour ce lien.");
      }
    } else if (response.status === 404) {
      notify("❓ Inconnu", "Ce lien n'a pas encore été analysé par VirusTotal.");
    } else {
      notify("❌ Erreur API", `Code : ${response.status}`);
    }
  } catch (error) {
    notify("❌ Erreur Connexion", "Impossible de joindre VirusTotal.");
  }
}

function notify(title, message) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icon.png",
    title: title,
    message: message,
    priority: 2
  });
}
