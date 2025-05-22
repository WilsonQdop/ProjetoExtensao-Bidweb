chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "verificar_url" && message.url) {
    verificarSite(message.url).then((inseguro) => {
      sendResponse({ inseguro });
    }).catch(() => {
      sendResponse({ inseguro: false });
    });

    return true; 
  }
});

async function verificarSite(url) {
  const [safeBrowsingInseguro, virusTotalInseguro] = await Promise.all([
    verificarSafeBrowsing(url),
    verificarVirusTotal(url)
  ]);

  return safeBrowsingInseguro || virusTotalInseguro;
}

async function verificarSafeBrowsing(url) {
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

function toBase64Url(input) {
  return btoa(input)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function verificarVirusTotal(url) {
  const virusTotalApiKey = "9f9589efd1d03537833541b211b53df70ec28bd8c2daf1bbadffaa65285b9b70";

  try {
    const response = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": virusTotalApiKey,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `url=${encodeURIComponent(url)}`
    });

    const postResult = await response.json();
    const base64UrlId = toBase64Url(url);
    const reportUrl = `https://www.virustotal.com/api/v3/urls/${base64UrlId}`;

    const reportResponse = await fetch(reportUrl, {
      method: "GET",
      headers: {
        "x-apikey": virusTotalApiKey
      }
    });

    const reportData = await reportResponse.json();

    if (reportData.error) {
      return false;
    }

    const analysisResults = reportData.data.attributes.last_analysis_results;
    let inseguro = false;

    for (const engine in analysisResults) {
      const result = analysisResults[engine];
      if (result.category === "malicious" || result.category === "suspicious") {
        inseguro = true;
      }
    }

    return inseguro;
  } catch {
    return false;
  }
}
