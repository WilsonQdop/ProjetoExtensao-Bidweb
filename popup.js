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
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
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

    if (verificacaoHomografos(urlAtual)) {
      statusElement.textContent = "⚠️ Cuidado! Este site pode ser perigoso.";
      statusElement.style.color = "red";
    } else {
      statusElement.textContent = "✅ Site seguro.";
      statusElement.style.color = "green";
    }

    chrome.storage.local.get(["inseguro", "urlAtual"], (data) => {
      if (data.urlAtual === urlAtual && data.inseguro) {
        statusElement.textContent = "❌ Site marcado como inseguro.";
        statusElement.style.color = "red";
      }
    });
  });
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
