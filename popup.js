document.addEventListener("DOMContentLoaded", () => {
  const status = document.getElementById("status");
  const url = document.getElementById("url");

  if (!status || !url) {
    console.error("Elementos HTML 'status' ou 'url' não encontrados.");
    return;
  }

  atualizarStatus(url, status);
});

function atualizarStatus(urlElement, statusElement) {
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const activeTab = tabs[0];

    if (!activeTab || !activeTab.url) {
      console.error("Aba ativa não encontrada.");
      urlElement.textContent = "URL indisponível.";
      statusElement.textContent = "Erro ao obter URL da aba.";
      statusElement.style.color = "gray";
      return;
    }

    const urlAtual = activeTab.url;
    urlElement.textContent = urlAtual;

    const verificacoesData = await chrome.storage.local.get("verificacoes");
    const verificacoes = verificacoesData.verificacoes || {};

    if (verificacoes.hasOwnProperty(urlAtual)) {
      const inseguro = verificacoes[urlAtual];

      if (inseguro) {
        statusElement.textContent = "❌ Site marcado como inseguro.";
        statusElement.style.color = "red";
      } else if (!verificacaoHomografos(urlAtual)) {
        statusElement.textContent = "✅ Site seguro.";
        statusElement.style.color = "green";
      }
    } else {
      const inseguro = await verificarSite(urlAtual);

      verificacoes[urlAtual] = inseguro;
      await chrome.storage.local.set({ verificacoes });

      if (inseguro) {
        statusElement.textContent = "❌ Site marcado como inseguro.";
        statusElement.style.color = "red";
      } else if (!verificacaoHomografos(urlAtual)) {
        statusElement.textContent = "✅ Site seguro.";
        statusElement.style.color = "green";
      }
    }

    if (verificacaoHomografos(urlAtual)) {
      statusElement.textContent = "⚠️ Cuidado! Este site pode ser perigoso.";
      statusElement.style.color = "red";
    }
  });
}

async function verificarSite(url) {
  const apiKey = "AIzaSyDgo_mMrtYZBFLRxFBVoeuaG8uw0E-fx5k";

  const response = await fetch(
    "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + apiKey,
    {
      method: "POST",
      body: JSON.stringify({
        client: {
          clientId: "extensao-seguranca",
          clientVersion: "1.0",
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }),
      headers: { "Content-Type": "application/json" },
    }
  );

  const data = await response.json();
  return !!data.matches;
}

function verificacaoHomografos(url) {
  let hostname;
  try {
    hostname = new URL(url).hostname;
  } catch (e) {
    console.error("URL inválida:", url);
    return false;
  }

  const punycodePattern = /^xn--/;
  const unicodeSpoofingPattern = /[^\x00-\x7F]/;

  return punycodePattern.test(hostname) || unicodeSpoofingPattern.test(hostname);
}
