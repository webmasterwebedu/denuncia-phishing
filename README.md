# 🛡️ Gerador de Denúncia de Phishing & SPAM (SOC / CSIRT)

Aplicação corporativa desenvolvida em **Streamlit** para análise forense simplificada de arquivos `.eml`, detecção de indicadores de comprometimento (IOCs), consultas automáticas de WHOIS/RDAP e geração ágil de denúncias de *abuse* (takedown e bloqueio).

---

## ✨ Funcionalidades Principais

- **Análise Completa de Cabeçalhos (.eml)**:
  - Extração de `Subject`, `Date`, `From`, `Return-Path`, `Reply-To` e `Message-ID`.
  - **Detecção de Spoofing**: Compara o remetente visível com o envelope real e analisa os resultados de **SPF, DKIM e DMARC**.
- **Rastreamento Inteligente de IP de Origem**:
  - Percorre todos os saltos (`Received:`) ignorando redes privadas/locais para identificar o IP público real de envio.
- **Inteligência de WHOIS & RDAP**:
  - Consulta automática de provedor/hosting, ASN e e-mails de `abuse` para o **IP remetente**, o **domínio remetente** e os **domínios maliciosos nos links**.
- **Inspeção de Links & URLs**:
  - Identificação de links mascarados (*mismatched links* onde o texto exibido difere do link real).
  - Opção de **Desarmar URLs (Defanging)** (`hxxps://`, `[.]`) para envio seguro sem bloqueio por antivírus.
- **🛡️ Integração com VirusTotal (API v3)**:
  - Consulta reputação de URLs e links em mais de **70 motores de antivírus e feeds de ameaças** em tempo real.
  - Verificação do hash **SHA-256** dos anexos contra a base global de malware do VirusTotal.
- **Inspeção de Anexos**:
  - Lista arquivos anexados, tipo MIME, tamanho e calcula o hash **SHA-256**, alertando sobre extensões perigosas.
- **Geração de Denúncias Prontas para Envio**:
  - Modelos profissionais em **Português (Brasil)** e **English (International)**.
  - Botão **✉️ Denunciar por E-mail** (`mailto:`) que preenche automaticamente Destinatário, Cópia (CC com CERT.br e registrars), Assunto e Corpo no cliente de e-mail padrão.

---

## 🚀 Instalação e Execução

### 🐧 Instalação Passo a Passo em VM Ubuntu Linux (20.04 / 22.04 / 24.04)

#### 1. Atualizar o sistema e instalar dependências do sistema operacional:
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git whois
```

#### 2. Clonar o repositório no diretório de sua preferência (ex: `/var/www/html/` ou `~/`):
```bash
sudo mkdir -p /var/www/html
cd /var/www/html
sudo git clone https://github.com/eletromidia/-Gerador-de-DenUncia-de-Phishing-e-SPAM.git denuncia-phishing
cd denuncia-phishing
```

#### 3. Criar e ativar o ambiente virtual (venv):
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 4. Instalar os pacotes Python necessários:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### 5. Executar em modo de teste:
```bash
streamlit run app.py --server.port 8501 --server.address 0.0.0.0
```
> Acesse no navegador: `http://<IP_DO_UBUNTU>:8501`

---

### ⚙️ Configurar como Serviço em Segundo Plano no Ubuntu (`systemd`)

Para manter a aplicação rodando 24/7 e iniciando automaticamente no boot do servidor Ubuntu:

#### 1. Criar o arquivo de serviço:
```bash
sudo nano /etc/systemd/system/denuncia-phishing.service
```

Cole o conteúdo abaixo (ajustando os caminhos se necessário):
```ini
[Unit]
Description=Streamlit App - Denuncia Phishing
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/www/html/denuncia-phishing
ExecStart=/var/www/html/denuncia-phishing/venv/bin/streamlit run app.py --server.address=127.0.0.1 --server.port=8501 --server.baseUrlPath=denuncia-phishing --server.headless=true --server.enableCORS=false --server.enableXsrfProtection=false
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

#### 2. Ativar e iniciar o serviço:
```bash
sudo systemctl daemon-reload
sudo systemctl enable denuncia-phishing
sudo systemctl start denuncia-phishing
sudo systemctl status denuncia-phishing
```

---

### 🌐 Configurar Proxy Reverso (Apache / Nginx na porta 80)

Se desejar acessar via porta 80 padrão (ex: `http://<IP>/denuncia-phishing`):

#### Exemplo com Apache:
```bash
sudo apt install -y apache2
sudo a2enmod proxy proxy_http proxy_wstunnel rewrite headers
```

Adicione no seu VirtualHost do Apache (`/etc/apache2/sites-available/000-default.conf`):
```apache
<Location /denuncia-phishing>
    ProxyPass http://127.0.0.1:8501/denuncia-phishing
    ProxyPassReverse http://127.0.0.1:8501/denuncia-phishing
</Location>

<Location /denuncia-phishing/_stcore/stream>
    ProxyPass ws://127.0.0.1:8501/denuncia-phishing/_stcore/stream
    ProxyPassReverse ws://127.0.0.1:8501/denuncia-phishing/_stcore/stream
</Location>
```

Reinicie o Apache:
```bash
sudo systemctl restart apache2
```

---

### 💻 Execução Local no Windows

```bash
# 1. Criar ambiente virtual
python -m venv venv
venv\Scripts\activate

# 2. Instalar dependências
pip install -r requirements.txt

# 3. Executar
streamlit run app.py
```

---

## 🎯 Fluxo de Denúncia

1. **Upload**: Carregue o arquivo `.eml` suspeito na aplicação.
2. **Diagnóstico**: A ferramenta avalia automaticamente o risco, identifica spoofing e contatos de abuse dos provedores.
3. **Envio**:
   - Clique em **✉️ Denunciar por E-mail** ou copie o texto estruturado com os IOCs.
   - Envie a notificação para o provedor de envio e coloque o CERT.br e registrars em cópia para derrubada da fraude.


