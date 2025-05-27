const statusText = document.getElementById("status-text");
const urlElement = document.getElementById("url");
const statusElement = document.getElementById("status");

document.addEventListener("DOMContentLoaded", () => {
  atualizarStatus(urlElement, statusElement);

  const themeButton = document.getElementById("toggle-theme");
  if (themeButton) {
    themeButton.addEventListener("click", toggleTheme);
  }

   chrome.storage.local.get("theme", (result) => {
    const theme = result.theme || "dark"; 
    const body = document.body;
    const themeButton = document.getElementById("toggle-theme");

    if (theme === "light") {
      body.classList.add("light-mode");
      themeButton.src = "icons/lua.png";
    } else {
      body.classList.remove("light-mode");
      themeButton.src = "icons/brilho.png";
    }
  });


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

function toggleTheme() {
  const body = document.body;
  const themeButton = document.getElementById("toggle-theme");

  body.classList.toggle("light-mode");

  const isLight = body.classList.contains("light-mode");

  themeButton.src = isLight ? "icons/lua.png" : "icons/brilho.png";

  chrome.storage.local.set({ theme: isLight ? "light" : "dark" });
}

