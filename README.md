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

### 1. Criar e ativar o ambiente virtual:

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Instalar dependências:
```bash
pip install -r requirements.txt
```

### 3. Executar o servidor:
```bash
streamlit run app.py --server.port 8501 --server.address 0.0.0.0
```

---

## 🎯 Fluxo de Denúncia

1. **Upload**: Carregue o arquivo `.eml` suspeito na aplicação.
2. **Diagnóstico**: A ferramenta avalia automaticamente o risco, identifica spoofing e contatos de abuse dos provedores.
3. **Envio**:
   - Clique em **✉️ Denunciar por E-mail** ou copie o texto estruturado com os IOCs.
   - Envie a notificação para o provedor de envio e coloque o CERT.br e registrars em cópia para derrubada da fraude.


