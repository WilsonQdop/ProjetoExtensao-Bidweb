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
  const [safeBrowseInseguro, virusTotalInseguro, abuseIpdbInseguro] = await Promise.all([
    verificarSafeBrowse(url),
    verificarVirusTotal(url),
    verificarAbuseIPDB(url)
  ]);

  return safeBrowseInseguro || virusTotalInseguro || abuseIpdbInseguro;
}

async function verificarSafeBrowse(url) {
  const apiKey = "AIzaSyDgo_mMrtYZBFLRxFBVoeuaG8uw0E-fx5k";

  const response = await fetch(
    "https://safeBrowse.googleapis.com/v4/threatMatches:find?key=" + apiKey,
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

function isIpAddress(ip) {
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3,3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3,3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

async function verificarAbuseIPDB(url) {
  const abuseIPDBApiKey = "21f0c06f86a8257564987bf927328ddb29ca84535b946c6c333171adb05cf0a81ade47e93c0c2f59";

  try {
    const ip = new URL(url).hostname;

    if (!isIpAddress(ip)) {
      console.warn(`Skipping AbuseIPDB check for non-IP hostname: ${ip}`);
      return false; 
    }

    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
      method: "GET",
      headers: {
        "Key": abuseIPDBApiKey,
        "Accept": "application/json"
      }
    });

    const data = await response.json();

    if (data.errors && data.errors.length > 0) {
        console.error("AbuseIPDB API error:", data.errors);
        return false;
    }

    return data.data.abuseConfidenceScore > 50;
  } catch (error) {
    console.error("Error during AbuseIPDB verification:", error);
    return false;
  }
}