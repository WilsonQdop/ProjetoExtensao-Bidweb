const powerIcon = document.getElementById('power-icon');
const statusText = document.getElementById('status-text');
const connectionStatus = document.getElementById('connection-status');

let conectado = false;

powerIcon.addEventListener('click', () => {
  conectado = !conectado;

  if (conectado) {
    statusText.textContent = 'PROTEGIDO';
    connectionStatus.textContent = 'Brasil - São Paulo';
  } else {
    statusText.textContent = 'NÃO PROTEGIDO';
    connectionStatus.textContent = 'Não conectado';
  }
});