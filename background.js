chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url.startsWith("http")) {
      const isUnsafe = await verificarSite(tab.url);
      chrome.storage.local.set({ inseguro: isUnsafe, urlAtual: tab.url });
    }
  });
  
  async function verificarSite(url) {
    const apiKey = "AIzaSyDgo_mMrtYZBFLRxFBVoeuaG8uw0E-fx5k";
  
    const response = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + apiKey, {
      method: "POST",
      body: JSON.stringify({
        client: {
          clientId: "extensao-seguranca",
          clientVersion: "1.0"
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      }),
      headers: { "Content-Type": "application/json" }
    });
  
    const data = await response.json();
    return !!data.matches;
  }