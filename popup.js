const statusText = document.getElementById("status-text");
const urlElement = document.getElementById("url");
const statusElement = document.getElementById("status");
const loadingSpinner = document.getElementById("loading-spinner");

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

    statusElement.textContent = "Verificando...";
    statusElement.style.color = "orange";
    loadingSpinner.style.display = "block";
    const response = await chrome.runtime.sendMessage({
      type: "verificar_url",
      url: urlAtual
    });
    loadingSpinner.style.display = "none";

    const inseguro = response.inseguro;

    if (inseguro) {
      statusElement.textContent = "❌ Site marcado como inseguro.";
      statusElement.style.color = "red";
      statusText.textContent = "NÃO PROTEGIDO";
    } else {
      statusElement.textContent = "✅ Site seguro.";
      statusElement.style.color = "green";
      statusText.textContent = "PROTEGIDO";
    }

  } catch (error) {
    console.error("Erro em atualizarStatus:", error);
    statusElement.textContent = "Erro ao verificar o site.";
    statusElement.style.color = "gray";
    loadingSpinner.style.display = "none";
  }
}

function toggleTheme() {
  const body = document.body;
  const themeButton = document.getElementById("toggle-theme");

  body.classList.toggle("light-mode");

  const isLight = body.classList.contains("light-mode");

  themeButton.src = isLight ? "icons/lua.png" : "icons/brilho.png";

  chrome.storage.local.set({ theme: isLight ? "light" : "dark" });
}