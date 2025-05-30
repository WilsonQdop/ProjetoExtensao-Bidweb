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
  const [safeBrowsingInseguro, virusTotalInseguro, abuseIPDBInseguro, homographInseguro] = await Promise.all([
    verificarSafeBrowsing(url),
    verificarVirusTotal(url),
    (async () => {
      try {
        const hostname = new URL(url).hostname;
        if (isIpAddress(hostname)) {
          return verificarAbuseIPDB(hostname);
        } else {
          const resolvedIp = await getIpFromDnsApi(hostname);
          if (resolvedIp) {
            return verificarAbuseIPDB(resolvedIp);
          }
          console.warn(`Não foi possível resolver o IP para ${hostname} via API de DNS.`);
          return false;
        }
      } catch (e) {
        console.error("Erro ao processar URL para AbuseIPDB:", e);
        return false;
      }
    })(),
    Promise.resolve(verificacaoHomografos(url)) 
  ]);

  return safeBrowsingInseguro || virusTotalInseguro || abuseIPDBInseguro || homographInseguro;
}

function verificacaoHomografos(url) {
  let hostname;
  try {
    hostname = new URL(url).hostname;
  } catch (e) {
    return false;
  }

  const punycodePattern = /^xn--/;
  const unicodeSpoofingPattern = /[^\x00-\x7F]/;

  return punycodePattern.test(hostname) || unicodeSpoofingPattern.test(hostname);
}

async function verificarSafeBrowsing(url) {
  const apiKey = "AIzaSyDgo_mMrtYZBFLRxFBVoeuaG8uw0E-fx5k";

  try {
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
  } catch (error) {
    console.error("Erro durante a verificação do Safe Browsing:", error);
    return false;
  }
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
    const submitResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": virusTotalApiKey,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `url=${encodeURIComponent(url)}`
    });

    const submitResult = await submitResponse.json();

    if (submitResult.error) {
      console.error("VirusTotal submission error:", submitResult.error);
      return false;
    }

    const analysisId = submitResult.data ? submitResult.data.id : null;

    if (!analysisId) {
        console.warn("VirusTotal did not return an analysis ID.");
        return false;
    }

    const reportUrl = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;
    let reportData = null;
    let attempts = 0;
    const maxAttempts = 5;
    const delay = 2000;

    while (attempts < maxAttempts) {
        const reportResponse = await fetch(reportUrl, {
            method: "GET",
            headers: {
                "x-apikey": virusTotalApiKey
            }
        });
        reportData = await reportResponse.json();

        if (reportData.data && reportData.data.attributes && reportData.data.attributes.status === 'completed') {
            break;
        }

        attempts++;
        await new Promise(res => setTimeout(res, delay));
    }

    if (!reportData || !reportData.data || !reportData.data.attributes || reportData.data.attributes.status !== 'completed') {
        console.warn("VirusTotal analysis did not complete in time or data is missing.");
        return false;
    }

    const analysisResults = reportData.data.attributes.results;
    let inseguro = false;

    for (const engine in analysisResults) {
      const result = analysisResults[engine];
      if (result.category === "malicious" || result.category === "suspicious") {
        inseguro = true;
        break;
      }
    }

    return inseguro;
  } catch (error) {
    console.error("Erro durante a verificação do VirusTotal:", error);
    return false;
  }
}


function isIpAddress(ip) {
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3,3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3,3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

function verificacaoHomografos(url) {
  let hostname;
  try {
    hostname = new URL(url).hostname;
  } catch (e) {
    return false;
  }

  const punycodePattern = /^xn--/;
  const unicodeSpoofingPattern = /[^\x00-\x7F]/;

  return punycodePattern.test(hostname) || unicodeSpoofingPattern.test(hostname);
}

async function getIpFromDnsApi(hostname) {
  const whoisXmlApiKey = "at_F7gOoGKG9fluEDeZMZbzZyMi0u5BG"; 
  const dnsApiUrl = `https://www.whoisxmlapi.com/whoisserver/DNSService?apiKey=${whoisXmlApiKey}&domainName=${encodeURIComponent(hostname)}&type=A,AAAA&outputFormat=JSON`;

  try {
    const response = await fetch(dnsApiUrl);

    if (!response.ok) {
      console.error(`Erro na API de DNS (WhoisXMLAPI): ${response.status} - ${response.statusText}`);
      const errorData = await response.json();
      console.error("Detalhes do erro da WhoisXMLAPI:", errorData);
      return null;
    }

    const data = await response.json();

    if (data.DNSData && data.DNSData.dnsRecords) {
      const ipRecord = data.DNSData.dnsRecords.find(record => record.dnsType === 'A' || record.dnsType === 'AAAA');

      if (ipRecord && ipRecord.address) {
        return ipRecord.address;
      }
    }

    console.warn(`Nenhum registro IP (A ou AAAA) encontrado para ${hostname} na WhoisXMLAPI.`);
    return null;

  } catch (error) {
    console.error("Erro ao obter IP da WhoisXMLAPI:", error);
    return null;
  }
}

async function verificarAbuseIPDB(ipAddress) {
  const abuseIPDBApiKey = "21f0c06f86a8257564987bf927328ddb29ca84535b946c6c333171adb05cf0a81ade47e93c0c2f59";

  try {
    if (!isIpAddress(ipAddress)) {
      console.warn(`Skipping AbuseIPDB check for non-IP: ${ipAddress}`);
      return false;
    }

    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ipAddress}`, {
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
    
    if (data.data && typeof data.data.abuseConfidenceScore === 'number') {
        return data.data.abuseConfidenceScore > 50;
    } else {
        console.warn("AbuseIPDB response missing expected data structure or score:", data);
        return false;
    }
  } catch (error) {
    console.error("Error during AbuseIPDB verification:", error);
    return false;
  }
}
