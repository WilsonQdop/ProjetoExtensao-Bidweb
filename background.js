chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "verificar_url" && message.url) {
    verificarSite(message.url).then((inseguro) => {
      sendResponse({ inseguro });
    }).catch((err) => {
      console.error("Erro ao verificar site:", err);
      sendResponse({ inseguro: false });
    });

    return true;
  }
});

async function verificarSite(url) {
  const apiKey = "AIzaSyDgo_mMrtYZBFLRxFBVoeuaG8uw0E-fx5k";

  const response = await fetch(
    "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + apiKey,
    {
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
    }
  );

  const data = await response.json();
  return !!data.matches;
}