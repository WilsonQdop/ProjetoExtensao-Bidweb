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

function queryTabs(queryOptions) {
  return new Promise((resolve) => {
    chrome.tabs.query(queryOptions, resolve);
  });
}

async function atualizarStatus(urlElement, statusElement) {
  try {
    const tabs = await queryTabs({ active: true, currentWindow: true });
    const activeTab = tabs[0];

    if (!activeTab || !activeTab.url) {
      urlElement.textContent = "URL indisponível.";
      statusElement.textContent = "Erro ao obter URL da aba.";
      statusElement.style.color = "gray";
      return;
    }

    const urlAtual = activeTab.url;
    urlElement.textContent = urlAtual;

    const response = await chrome.runtime.sendMessage({
      type: "verificar_url",
      url: urlAtual
    });

    const inseguro = response.inseguro;

    if (inseguro) {
      statusElement.textContent = "❌ Site marcado como inseguro.";
      statusElement.style.color = "red";
      statusText.textContent = "NÃO PROTEGIDO";
    } else if (!verificacaoHomografos(urlAtual)) {
      statusElement.textContent = "✅ Site seguro.";
      statusElement.style.color = "green";
      statusText.textContent = "PROTEGIDO";
    }

    if (verificacaoHomografos(urlAtual)) {
      statusElement.textContent = "⚠️ Cuidado! Este site pode ser perigoso.";
      statusElement.style.color = "red";
      statusText.textContent = "NÃO PROTEGIDO";
    }
  } catch (error) {
    console.error("Erro em atualizarStatus:", error);
    statusElement.textContent = "Erro ao verificar o site.";
    statusElement.style.color = "gray";
  }
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
