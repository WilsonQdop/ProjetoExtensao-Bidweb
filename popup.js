document.addEventListener("DOMContentLoaded", () => {
  chrome.storage.local.get(["inseguro", "urlAtual"], (data) => {
    const status = document.getElementById("status");
    const url = document.getElementById("url");

    if (!status || !url) {
      console.error("Elementos HTML 'status' ou 'url' não encontrados.");
      return;
    }

    if (!data || !data.urlAtual) {
      console.error("Dados não encontrados no chrome.storage.local.");
      status.textContent = "Erro ao carregar os dados.";
      status.style.color = "gray";
      return;
    }

    url.textContent = data.urlAtual;

    if (verificacaoHomografos(data.urlAtual)) {
      status.textContent = "⚠️ Cuidado! Este site pode ser perigoso.";
      status.style.color = "red";
    } else {
      status.textContent = "✅ Site seguro.";
      status.style.color = "green";
    }
  });
});

function verificacaoHomografos(url) {
  
  const normalizedUrl = url.replace(/^https?:\/\//, '');
  const punycodePattern = /^xn--/;
  const unicodeSpoofingPattern = /[^\x00-\x7F]/;

  return punycodePattern.test(normalizedUrl) || unicodeSpoofingPattern.test(normalizedUrl);
}