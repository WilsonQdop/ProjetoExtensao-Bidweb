const powerIcon = document.getElementById("power-icon");
const statusText = document.getElementById("status-text");
const url = document.getElementById("url");
const status = document.getElementById("status");
const btnVerificar = document.getElementById("btn-verificar");

powerIcon.addEventListener("click", () => {
  atualizarStatus(url, status);
});

btnVerificar.addEventListener("click", async () => {
  try {
    const granted = await chrome.permissions.request({
      permissions: ["tabs"],
      origins: ["<all_urls>"]
    });

    if (granted) {
      atualizarStatus(url, status);
    } else {
      alert("Permissão negada. Não é possível verificar a URL.");
    }
  } catch (e) {
    console.error("Erro ao pedir permissão:", e);
  }
});


async function atualizarStatus(urlElement, statusElement) {
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const activeTab = tabs[0];

    if (!activeTab || !activeTab.url) {
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
        statusText.textContent = "NÃO PROTEGIDO";
      } else if (!verificacaoHomografos(urlAtual)) {
        statusElement.textContent = "✅ Site seguro.";
        statusElement.style.color = "green";
        statusText.textContent = "PROTEGIDO";
      }
    } else {
      const inseguro = await verificarSite(urlAtual);

      verificacoes[urlAtual] = inseguro;
      await chrome.storage.local.set({ verificacoes });

      if (inseguro) {
        statusElement.textContent = "❌ Site marcado como inseguro.";
        statusElement.style.color = "red";
        statusText.textContent = "NÃO PROTEGIDO";
      } else if (!verificacaoHomografos(urlAtual)) {
        statusElement.textContent = "✅ Site seguro.";
        statusElement.style.color = "green";
        statusText.textContent = "PROTEGIDO";
      }
    }

    if (verificacaoHomografos(urlAtual)) {
      statusElement.textContent = "⚠️ Cuidado! Este site pode ser perigoso.";
      statusElement.style.color = "red";
      statusText.textContent = "NÃO PROTEGIDO";
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
    return false;
  }

  const punycodePattern = /^xn--/;
  const unicodeSpoofingPattern = /[^\x00-\x7F]/;

  return punycodePattern.test(hostname) || unicodeSpoofingPattern.test(hostname);
}