# Gerador de Denúncia de Phishing

Este projeto é uma aplicação em Streamlit para analisar arquivos `.eml` de phishing, extrair indicadores do e-mail e montar um texto de denúncia para enviar ao provedor ou à equipe de abuso.

## Funcionalidades

- Upload de arquivos `.eml`
- Extração de remetente, IP de origem, data/hora e corpo do e-mail
- Identificação de domínios encontrados nos links
- Busca automática de contatos de abuse via WHOIS
- Geração de texto pronto para denúncia

## Requisitos

- Python 3.9+
- pip

## Como instalar

```bash
python -m venv venv
```

No Windows:

```bash
venv\Scripts\activate
```

No macOS/Linux:

```bash
source venv/bin/activate
```

Em seguida:

```bash
pip install -r requirements.txt
```

## Como executar

```bash
streamlit run app.py
```

## Como usar

1. Abra a aplicação no navegador.
2. Faça upload de um arquivo `.eml`.
3. Veja os indicadores extraídos e copie o texto de denúncia gerado.

## Observação

Este projeto foi preparado para publicação no GitHub, mas ainda não foi enviado para o repositório remoto.
