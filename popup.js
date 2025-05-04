chrome.storage.local.get(["inseguro", "urlAtual"], (data) => {
    const status = document.getElementById("status");
    const url = document.getElementById("url");
  
    url.textContent = data.urlAtual;
  
    if (data.inseguro) {
      status.textContent = "⚠️ Cuidado! Este site pode ser perigoso.";
      status.style.color = "red";
    } else {
      status.textContent = "✅ Site seguro.";
      status.style.color = "green";
    }
  });