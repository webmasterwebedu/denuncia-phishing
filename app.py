import streamlit as st
import email
from email import policy
from email.utils import parsedate_to_datetime, parseaddr
import re
import ipaddress
import hashlib
import json
import urllib.request
from urllib.parse import urlparse, quote
from html.parser import HTMLParser
import whois

# Configuração da página Streamlit
st.set_page_config(
    page_title="Gerador de Denúncia de Phishing & SPAM",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ----------------- PARSER HTML NATIVO ----------------- #

class SimpleHTMLLinkExtractor(HTMLParser):
    """Extrator de links e texto HTML usando exclusivamente a biblioteca nativa html.parser."""
    def __init__(self):
        super().__init__()
        self.links = []  # lista de dicts com url, text
        self.current_href = None
        self.current_text = []
        self.all_text = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'a':
            for attr, val in attrs:
                if attr.lower() == 'href' and val:
                    self.current_href = val.strip()
                    self.current_text = []

    def handle_data(self, data):
        self.all_text.append(data)
        if self.current_href is not None:
            self.current_text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == 'a' and self.current_href is not None:
            text = " ".join("".join(self.current_text).split())
            self.links.append((self.current_href, text))
            self.current_href = None
            self.current_text = []

    def get_text(self):
        return " ".join("".join(self.all_text).split())

# ----------------- FUNÇÕES AUXILIARES ----------------- #

def is_public_ip(ip_str: str) -> bool:
    """Verifica se um endereço IP é público/roteável na internet."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return not (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_reserved or
            ip_obj.is_multicast or
            ip_obj.is_unspecified
        )
    except ValueError:
        return False

def are_domains_aligned(dom1: str, dom2: str) -> bool:
    """Verifica se dois domínios pertencem à mesma organização ou se um é subdomínio do outro (ex: mail.netskope.com e netskope.com)."""
    if not dom1 or not dom2:
        return False
    d1 = dom1.lower().strip()
    d2 = dom2.lower().strip()
    if d1 == d2:
        return True
    if d1.endswith("." + d2) or d2.endswith("." + d1):
        return True
    return False

def extract_origin_ips(msg) -> tuple[str, list[str]]:
    """Extrai todos os IPs públicos encontrados nos cabeçalhos Received e outros cabeçalhos de origem."""
    public_ips = []
    
    # 1. Checa cabeçalhos diretos comuns
    direct_headers = ["X-Originating-IP", "X-SenderIP", "X-Client-IP", "X-Remote-IP"]
    for header in direct_headers:
        val = msg.get(header)
        if val:
            found_ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', val)
            for ip in found_ips:
                if is_public_ip(ip) and ip not in public_ips:
                    public_ips.append(ip)
    
    # 2. Percorre cabeçalhos Received (do mais antigo/inferior para o mais recente)
    received_headers = msg.get_all("Received", [])
    for rec in reversed(received_headers):
        found_ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', rec)
        for ip in found_ips:
            if is_public_ip(ip) and ip not in public_ips:
                public_ips.append(ip)
                
    main_ip = public_ips[0] if public_ips else "Não identificado"
    return main_ip, public_ips

def parse_auth_results(msg) -> dict:
    """Analisa os cabeçalhos Authentication-Results e Received-SPF para verificar SPF, DKIM e DMARC."""
    auth_data = {
        "spf": "Não identificado",
        "dkim": "Não identificado",
        "dmarc": "Não identificado",
        "is_spoofed_suspect": False
    }
    
    auth_results = str(msg.get("Authentication-Results", "") or "")
    received_spf = str(msg.get("Received-SPF", "") or "")
    
    combined = f"{auth_results} {received_spf}".lower()
    
    # SPF
    spf_match = re.search(r'spf=(\w+)', combined)
    if spf_match:
        auth_data["spf"] = spf_match.group(1).upper()
    elif "spf: pass" in combined or "spf=pass" in combined:
        auth_data["spf"] = "PASS"
    elif "spf: fail" in combined or "spf=fail" in combined:
        auth_data["spf"] = "FAIL"
    elif "spf: softfail" in combined or "spf=softfail" in combined:
        auth_data["spf"] = "SOFTFAIL"
        
    # DKIM
    dkim_match = re.search(r'dkim=(\w+)', combined)
    if dkim_match:
        auth_data["dkim"] = dkim_match.group(1).upper()
    elif "dkim: pass" in combined or "dkim=pass" in combined:
        auth_data["dkim"] = "PASS"
    elif "dkim: fail" in combined or "dkim=fail" in combined:
        auth_data["dkim"] = "FAIL"
        
    # DMARC
    dmarc_match = re.search(r'dmarc=(\w+)', combined)
    if dmarc_match:
        auth_data["dmarc"] = dmarc_match.group(1).upper()
    elif "dmarc: pass" in combined or "dmarc=pass" in combined:
        auth_data["dmarc"] = "PASS"
    elif "dmarc: fail" in combined or "dmarc=fail" in combined:
        auth_data["dmarc"] = "FAIL"
        
    if auth_data["spf"] in ["FAIL", "SOFTFAIL"] or auth_data["dkim"] == "FAIL" or auth_data["dmarc"] == "FAIL":
        auth_data["is_spoofed_suspect"] = True
        
    return auth_data


def defang_text(text: str) -> str:
    """Desarma URLs, domínios e e-mails para envio seguro de denúncia sem ativar antivírus ou filtros."""
    if not text:
        return text
    text = re.sub(r'https://', 'hxxps://', text, flags=re.IGNORECASE)
    text = re.sub(r'http://', 'hxxp://', text, flags=re.IGNORECASE)
    text = re.sub(r'ftp://', 'fxp://', text, flags=re.IGNORECASE)
    text = re.sub(r'(\w+)\.(\w+)', r'\1[.]\2', text)
    return text

def extract_body_and_links(msg) -> tuple[str, list[dict], list[str]]:
    """Extrai texto e HTML do corpo, identifica links reais vs texto âncora e lista domínios únicos."""
    body_text = ""
    body_html = ""
    links = []
    unique_domains = []
    
    ignored_domains = {
        "schemas.microsoft.com", "schemas.openxmlformats.org", "www.w3.org", 
        "w3.org", "xml.org", "purl.org", "schemas.xmlsoap.org", "fonts.googleapis.com", 
        "fonts.gstatic.com", "schema.org"
    }

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            charset = part.get_content_charset() or 'utf-8'
            payload = part.get_payload(decode=True)
            if payload:
                try:
                    decoded = payload.decode(charset, errors='replace')
                except Exception:
                    decoded = payload.decode('latin-1', errors='replace')
                    
                if content_type == "text/plain":
                    body_text += "\n" + decoded
                elif content_type == "text/html":
                    body_html += "\n" + decoded
    else:
        content_type = msg.get_content_type()
        charset = msg.get_content_charset() or 'utf-8'
        payload = msg.get_payload(decode=True)
        if payload:
            try:
                decoded = payload.decode(charset, errors='replace')
            except Exception:
                decoded = payload.decode('latin-1', errors='replace')
            if content_type == "text/html":
                body_html = decoded
            else:
                body_text = decoded

    # Extrai links de HTML usando o parser nativo
    html_text_extracted = ""
    if body_html:
        try:
            parser = SimpleHTMLLinkExtractor()
            parser.feed(body_html)
            html_text_extracted = parser.get_text()
            for href, anchor_text in parser.links:
                if href.startswith(('http://', 'https://')):
                    parsed = urlparse(href)
                    domain = parsed.netloc.lower().split(':')[0]
                    if domain and domain not in ignored_domains:
                        mismatched = False
                        if re.search(r'\w+\.\w+', anchor_text) and not anchor_text.startswith(('http://', 'https://')):
                            anchor_url = "http://" + anchor_text
                            try:
                                anchor_domain = urlparse(anchor_url).netloc.lower().split(':')[0]
                                if anchor_domain and anchor_domain != domain:
                                    mismatched = True
                            except Exception:
                                pass
                        links.append({
                            "url": href,
                            "domain": domain,
                            "text": anchor_text or "[Sem texto]",
                            "mismatched": mismatched
                        })
                        if domain not in unique_domains:
                            unique_domains.append(domain)
        except Exception:
            pass

    # Extrai URLs adicionais em texto puro
    search_text = body_text + "\n" + body_html
    raw_urls = re.findall(r'(https?://[^\s<>"\')]+)', search_text)
    for u in raw_urls:
        clean_u = re.sub(r'[\"\'>)]+$', '', u).strip()
        parsed = urlparse(clean_u)
        domain = parsed.netloc.lower().split(':')[0]
        if domain and domain not in ignored_domains:
            if not any(l['url'] == clean_u for l in links):
                links.append({
                    "url": clean_u,
                    "domain": domain,
                    "text": "[Link no texto]",
                    "mismatched": False
                })
            if domain not in unique_domains:
                unique_domains.append(domain)

    full_body = body_text.strip() if body_text.strip() else html_text_extracted
    return full_body, links, unique_domains

def extract_attachments(msg) -> list[dict]:
    """Identifica anexos, seus tipos, tamanhos e hashes SHA-256."""
    attachments = []
    dangerous_exts = {
        '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.iso', 
        '.img', '.html', '.htm', '.zip', '.rar', '.7z', '.hta', '.ps1', '.lnk'
    }
    
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()
            if filename or "attachment" in content_disposition.lower():
                payload = part.get_payload(decode=True)
                if payload:
                    sha256 = hashlib.sha256(payload).hexdigest()
                    size_kb = len(payload) / 1024
                    fname = filename or "anexo_sem_nome"
                    ext = "." + fname.split(".")[-1].lower() if "." in fname else ""
                    is_suspicious = ext in dangerous_exts
                    attachments.append({
                        "filename": fname,
                        "content_type": part.get_content_type(),
                        "size_kb": f"{size_kb:.2f} KB",
                        "sha256": sha256,
                        "is_suspicious": is_suspicious
                    })
    return attachments

@st.cache_data(ttl=3600, show_spinner=False)
def lookup_domain_whois(domain: str) -> dict:
    """Consulta WHOIS do domínio para encontrar abuse emails e informações do registrar."""
    info = {
        "domain": domain,
        "registrar": "Não identificado",
        "abuse_emails": [],
        "org": "Não identificado"
    }
    try:
        w = whois.whois(domain)
        if w:
            if hasattr(w, 'registrar') and w.registrar:
                info["registrar"] = w.registrar if isinstance(w.registrar, str) else w.registrar[0]
            if hasattr(w, 'org') and w.org:
                info["org"] = w.org if isinstance(w.org, str) else w.org[0]
            
            emails = []
            if hasattr(w, 'emails') and w.emails:
                if isinstance(w.emails, list):
                    emails = [e.lower() for e in w.emails if isinstance(e, str)]
                elif isinstance(w.emails, str):
                    emails = [w.emails.lower()]
            
            abuse_emails = [e for e in emails if "abuse" in e or "security" in e or "noc" in e]
            if not abuse_emails and emails:
                abuse_emails = emails
            info["abuse_emails"] = list(set(abuse_emails))
    except Exception:
        pass
    return info

@st.cache_data(ttl=3600, show_spinner=False)
def lookup_ip_rdap(ip: str) -> dict:
    """Consulta RDAP/Geolocalização do IP usando exclusivamente bibliotecas nativas."""
    data = {
        "ip": ip,
        "org": "Não identificado",
        "asn": "Não identificado",
        "country": "Não identificado",
        "abuse_emails": []
    }
    if not is_public_ip(ip):
        return data
        
    # Consulta via RDAP oficial usando urllib nativo
    try:
        req = urllib.request.Request(
            f"https://rdap.arin.net/registry/ip/{ip}",
            headers={"Accept": "application/json", "User-Agent": "PhishingAnalyzer/1.0"}
        )
        with urllib.request.urlopen(req, timeout=4) as response:
            if response.status == 200:
                rdap_json = json.loads(response.read().decode('utf-8'))
                data["org"] = rdap_json.get("name", "Não identificado")
                entities = rdap_json.get("entities", [])
                for ent in entities:
                    roles = ent.get("roles", [])
                    vcard = ent.get("vcardArray", [])
                    if "abuse" in roles and len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "email" and len(item) > 3:
                                email_val = item[3].lower()
                                if email_val not in data["abuse_emails"]:
                                    data["abuse_emails"].append(email_val)
    except Exception:
        pass

    # Fallback rápido via ip-api usando urllib nativo
    if data["org"] == "Não identificado":
        try:
            req2 = urllib.request.Request(
                f"http://ip-api.com/json/{ip}?fields=status,country,org,as,query",
                headers={"User-Agent": "PhishingAnalyzer/1.0"}
            )
            with urllib.request.urlopen(req2, timeout=3) as response2:
                if response2.status == 200:
                    j = json.loads(response2.read().decode('utf-8'))
                    if j.get("status") == "success":
                        data["org"] = j.get("org", "Não identificado")
                        data["asn"] = j.get("as", "Não identificado")
                        data["country"] = j.get("country", "Não identificado")
        except Exception:
            pass

    return data

# ----------------- INTERFACE PRINCIPAL ----------------- #

st.sidebar.markdown("## ⚙️ Configurações")

idioma = st.sidebar.selectbox(
    "🌐 Idioma da Denúncia:",
    ["Português (Brasil)", "English (International)"],
    help="Escolha o idioma do texto da denúncia. Provedores internacionais exigem inglês."
)

tipo_incidente = st.sidebar.selectbox(
    "⚠️ Classificação do Incidente:",
    [
        "Phishing / Roubo de Credenciais",
        "SPAM em Massa / E-mail Não Solicitado",
        "Conta de E-mail Comprometida",
        "Distribuição de Malware / Anexo Suspeito"
    ]
)

aplicar_defang = st.sidebar.checkbox(
    "🔒 Desarmar URLs e Domínios (Defang)",
    value=True,
    help="Substitui 'http://' por 'hxxp://' e '.' por '[.]' para evitar cliques acidentais e bloqueio por antivírus ao enviar a denúncia."
)

sua_equipe = st.sidebar.text_input(
    "🏢 Assinatura da Denúncia:",
    value="Equipe de Segurança da Informação (SOC / CSIRT)",
    help="Identificação que aparecerá no final do e-mail de denúncia."
)

st.sidebar.markdown("---")
st.sidebar.markdown(
    """
    **📌 Recomendações:**
    - Nunca acesse links suspeitos em sua estação de trabalho.
    - Se possível, anexe o arquivo `.eml` original na denúncia.
    - Notifique também o [CERT.br](https://www.cert.br/) em `mail-abuse@cert.br`.
    """
)

# Cabeçalho Principal
st.title("🛡️ Central de Análise e Denúncia de Phishing & SPAM")
st.markdown("Faça o upload de uma mensagem `.eml` para extrair indicadores técnicos (IOCs), consultar WHOIS/RDAP e gerar a denúncia pronta para os órgãos de segurança.")

uploaded_file = st.file_uploader("📂 Arraste ou selecione o arquivo .eml para análise", type=["eml"])

if uploaded_file is None:
    st.markdown("---")
    col_info1, col_info2 = st.columns(2)
    with col_info1:
        st.markdown("""
        ### 🔍 Análise Forense e Anti-Spoofing
        * **Detecção instantânea de falhas em SPF, DKIM e DMARC.**
        * **Comparação automática de remetente visível (`From`) com o envelope real (`Return-Path`).**
        * **Rastreamento dos saltos (`Received:`) para achar o IP público real de envio.**

        ### 🌐 Inteligência de WHOIS e Provedores
        * **Consulta automática de IP / RDAP** (identifica se veio de AWS, DigitalOcean, Locaweb, etc.).
        * **Consulta de WHOIS de Domínios** dos links no corpo do e-mail.
        """)
        
    with col_info2:
        st.markdown("""
        ### 🎯 Geração e Envio Ágil de Denúncia
        * **Para (TO):** Provedor de hospedagem do IP de disparo (para suspensão).
        * **Em Cópia (CC):** Registrars dos links falsos e `mail-abuse@cert.br` (**CERT.br**).
        * **Botão ✉️ Denunciar por E-mail:** Abre o cliente de e-mail com tudo preenchido em 1 clique.
        * **Desarmamento de URLs (Defang):** Previne cliques acidentais e bloqueio por antivírus (`hxxps://`, `[.]`).
        * **Inspeção de Anexos:** Cálculo de hash **SHA-256** e alerta de arquivos de alto risco (`.exe`, `.iso`, `.zip`, etc.).
        """)

if uploaded_file is not None:
    try:
        raw_email = uploaded_file.read()
        msg = email.message_from_bytes(raw_email, policy=policy.default)
        
        # 1. Extração dos Cabeçalhos Principais
        subject = msg.get("Subject", "(Sem Assunto)")
        from_raw = msg.get("From", "")
        from_display, sender_email = parseaddr(from_raw)
        if not sender_email:
            sender_email = from_raw

        return_path_raw = msg.get("Return-Path", "")
        _, return_path = parseaddr(return_path_raw)
        
        reply_to_raw = msg.get("Reply-To", "")
        _, reply_to = parseaddr(reply_to_raw)
        
        date_header = msg.get("Date")
        if date_header:
            try:
                dt = parsedate_to_datetime(date_header)
                data_hora = dt.strftime("%d/%m/%Y às %H:%M:%S") + f" ({dt.strftime('%z')})"
            except Exception:
                data_hora = str(date_header)
        else:
            data_hora = "Data não identificada"

        # 2. Rastreamento de IP
        ip_origem, todos_ips = extract_origin_ips(msg)
        
        # 3. Autenticação SPF / DKIM / DMARC
        auth_info = parse_auth_results(msg)
        
        # 4. Corpo, Links e Domínios
        body_text, links_detectados, dominios_links = extract_body_and_links(msg)
        
        # 5. Anexos
        anexos = extract_attachments(msg)
        
        # 6. Domínio do Remetente e Provedor
        remetente_dominio = sender_email.split('@')[-1].lower() if '@' in sender_email else "desconhecido.com"
        return_path_dominio = return_path.split('@')[-1].lower() if '@' in return_path else ""
        
        # Detecção de Spoofing e Autenticidade
        spoofing_detectado = False
        autenticacao_valida = (auth_info["spf"] == "PASS" and auth_info["dkim"] == "PASS" and auth_info["dmarc"] == "PASS")
        alinhamento_valido = are_domains_aligned(return_path_dominio, remetente_dominio)
        
        if auth_info["is_spoofed_suspect"]:
            spoofing_detectado = True
        elif return_path_dominio and remetente_dominio:
            if not alinhamento_valido and not (autenticacao_valida and auth_info["dmarc"] == "PASS"):
                spoofing_detectado = True

        # 7. Consultas WHOIS & RDAP
        with st.spinner("🔍 Consultando bases WHOIS e RDAP para identificar provedores e contatos de abuse..."):
            # WHOIS do IP de Origem
            ip_info = lookup_ip_rdap(ip_origem) if ip_origem != "Não identificado" else {}
            
            # WHOIS dos Domínios dos Links
            dominios_info = []
            todos_abuse_links = set()
            for dom in dominios_links[:5]:
                winfo = lookup_domain_whois(dom)
                dominios_info.append(winfo)
                for email_ab in winfo.get("abuse_emails", []):
                    todos_abuse_links.add(email_ab)
            
            # WHOIS do Domínio do Remetente
            remetente_whois = lookup_domain_whois(remetente_dominio)
            for email_ab in remetente_whois.get("abuse_emails", []):
                todos_abuse_links.add(email_ab)

        # 8. Destinatários Sugeridos para Denúncia
        destinatarios_to = []
        destinatarios_cc = []
        
        if ip_info.get("abuse_emails"):
            destinatarios_to.extend(ip_info["abuse_emails"])
        elif remetente_whois.get("abuse_emails"):
            destinatarios_to.extend(remetente_whois["abuse_emails"])
        else:
            destinatarios_to.append(f"abuse@{remetente_dominio}")
            
        for ab in todos_abuse_links:
            if ab not in destinatarios_to:
                destinatarios_cc.append(ab)
                
        cert_br = "mail-abuse@cert.br"
        if cert_br not in destinatarios_cc and cert_br not in destinatarios_to:
            destinatarios_cc.append(cert_br)
            
        to_str = ", ".join(destinatarios_to)
        cc_str = ", ".join(destinatarios_cc)

        # --- AVALIAÇÃO DE RISCO ---
        motivos_risco = []
        if spoofing_detectado:
            motivos_risco.append("⚠️ Possível Remetente Forjado (Spoofing) ou Falha em SPF/DKIM/DMARC")
        if any(l.get("mismatched") for l in links_detectados):
            motivos_risco.append("⚠️ Link Discrepante Detectado (Texto âncora difere do destino real)")
        if any(a.get("is_suspicious") for a in anexos):
            motivos_risco.append("⚠️ Anexo com extensão de alto risco detectado")
            
        st.markdown("---")
        col_res1, col_res2 = st.columns([1, 2])
        with col_res1:
            if motivos_risco:
                st.metric(label="Diagnóstico da Mensagem", value="🔴 Suspeita / Phishing", delta="Alto Risco", delta_color="inverse")
            elif autenticacao_valida and (alinhamento_valido or auth_info["dmarc"] == "PASS"):
                st.metric(label="Diagnóstico da Mensagem", value="🟢 Autêntica / Legítima", delta="SPF, DKIM e DMARC Válidos")
            else:
                st.metric(label="Diagnóstico da Mensagem", value="🟡 Sem Alertas Graves", delta="Informativa")
        with col_res2:
            st.markdown(f"**Assunto:** `{subject}`")
            st.markdown(f"**Remetente:** `{sender_email}` | **IP de Envio:** `{ip_origem}` ({ip_info.get('org', 'Desconhecido')})")

        # 9. GERAÇÃO DOS MODELOS DE DENÚNCIA
        links_formatados = "\n".join([f"- {defang_text(l['url']) if aplicar_defang else l['url']} (Domínio: {defang_text(l['domain']) if aplicar_defang else l['domain']})" for l in links_detectados]) if links_detectados else "Nenhum link detectado."
        anexos_formatados = "\n".join([f"- {a['filename']} (SHA256: {a['sha256']}, Tamanho: {a['size_kb']})" for a in anexos]) if anexos else "Nenhum anexo detectado."
        
        sender_clean = defang_text(sender_email) if aplicar_defang else sender_email
        ip_clean = defang_text(ip_origem) if aplicar_defang else ip_origem
        
        if idioma == "Português (Brasil)":
            assunto_denuncia = f"[DENÚNCIA DE ABUSE] {tipo_incidente} - {sender_clean}"
            corpo_denuncia = f"""Prezada Equipe de Segurança e Abuse,

Gostaria de formalizar uma denúncia de incidente de segurança ({tipo_incidente}) envolvendo a infraestrutura sob sua responsabilidade.

DETALHES DO INCIDENTE:
==================================================
* Assunto Original: {subject}
* Remetente (From): {sender_clean}
* Envelope Sender (Return-Path): {defang_text(return_path) if (return_path and aplicar_defang) else (return_path or "N/D")}
* IP de Origem do Envio: {ip_clean}
* Provedor / ASN do IP: {ip_info.get('org', 'Não identificado')} ({ip_info.get('asn', 'N/D')})
* Data e Hora do Disparo: {data_hora}
* Autenticação: SPF: {auth_info['spf']} | DKIM: {auth_info['dkim']} | DMARC: {auth_info['dmarc']}

INDICADORES DE COMPROMETIMENTO (IOCs):
==================================================
URLs e Domínios Maliciosos:
{links_formatados}

Arquivos Anexados:
{anexos_formatados}

SOLICITAÇÃO:
==================================================
Solicitamos a verificação imediata, suspensão dos serviços abusivos e bloqueio da conta ou host comprometido para mitigar novos ataques aos usuários.

O arquivo .eml original completo com todos os cabeçalhos pode ser fornecido mediante solicitação.

Atenciosamente,
{sua_equipe}"""
        else:
            assunto_denuncia = f"[ABUSE REPORT] {tipo_incidente} - {sender_clean}"
            corpo_denuncia = f"""Dear Security / Abuse Team,

We would like to report a security incident ({tipo_incidente}) originating from or abusing your infrastructure.

INCIDENT DETAILS:
==================================================
* Original Subject: {subject}
* From: {sender_clean}
* Return-Path: {defang_text(return_path) if (return_path and aplicar_defang) else (return_path or "N/A")}
* Originating IP: {ip_clean}
* IP Organization / ASN: {ip_info.get('org', 'Unidentified')} ({ip_info.get('asn', 'N/A')})
* Date / Time: {data_hora}
* Authentication: SPF: {auth_info['spf']} | DKIM: {auth_info['dkim']} | DMARC: {auth_info['dmarc']}

INDICATORS OF COMPROMISE (IOCs):
==================================================
Detected URLs & Domains:
{links_formatados}

Attachments:
{anexos_formatados}

REQUEST:
==================================================
We kindly request you investigate this incident, take down any fraudulent hosts or domains, and terminate the compromised accounts to prevent further malicious activity.

The raw original .eml file is available upon request.

Sincerely,
{sua_equipe}"""

        # Link mailto formatado
        mailto_subject = quote(assunto_denuncia)
        mailto_body = quote(corpo_denuncia)
        mailto_to = quote(to_str)
        mailto_cc = quote(cc_str)
        mailto_link = f"mailto:{mailto_to}?cc={mailto_cc}&subject={mailto_subject}&body={mailto_body}"

        # --- SEÇÃO DE DESTINATÁRIOS E AÇÃO RÁPIDA ---
        st.subheader("🎯 Para Quem Denunciar?")
        col_dest1, col_dest2 = st.columns(2)
        with col_dest1:
            st.info(f"**Para (TO) - Provedor de Envio / Hosting:**\n`{to_str}`")
        with col_dest2:
            st.warning(f"**Em Cópia (CC) - Registrar / Takedown / CERT.br:**\n`{cc_str}`")

        col_act1, col_act2 = st.columns([1, 4])
        with col_act1:
            st.markdown(
                f'''<a href="{mailto_link}" target="_blank" style="text-decoration:none;">
                    <button style="width:100%; height:45px; background-color:#0066cc; color:white; border:none; border-radius:6px; font-weight:bold; cursor:pointer;">
                        ✉️ Denunciar por E-mail
                    </button>
                </a>''',
                unsafe_allow_html=True
            )
        with col_act2:
            st.caption("Ao clicar em 'Denunciar por E-mail', seu cliente padrão (ex: Outlook) será aberto com os destinatários, assunto e corpo já preenchidos para envio da denúncia.")

        # --- ABAS DE DETALHES ---
        tab_denuncia, tab_auth, tab_whois, tab_links, tab_anexos, tab_raw = st.tabs([
            "📋 Texto da Denúncia",
            "🛡️ Diagnóstico & Autenticação",
            "🌐 Inteligência WHOIS & IP",
            "🔗 Links & Domínios",
            "📎 Anexos & Hashes",
            "📜 Cabeçalhos Brutos"
        ])

        with tab_denuncia:
            st.markdown(f"**Assunto sugerido:** `{assunto_denuncia}`")
            st.text_area("Copie o texto estruturado abaixo:", value=corpo_denuncia, height=360)

        with tab_auth:
            st.subheader("Verificação de Spoofing e Cabeçalhos de Segurança")
            col_a1, col_a2, col_a3 = st.columns(3)
            with col_a1:
                st.metric("SPF", auth_info["spf"])
            with col_a2:
                st.metric("DKIM", auth_info["dkim"])
            with col_a3:
                st.metric("DMARC", auth_info["dmarc"])

            st.markdown("### Análise de Identidade")
            st.markdown(f"- **From (Exibido):** `{from_raw}`")
            st.markdown(f"- **Return-Path (Envelope Real):** `{return_path_raw or 'Não especificado'}`")
            st.markdown(f"- **Reply-To:** `{reply_to_raw or 'Igual ao remetente'}`")
            
            if spoofing_detectado:
                st.error("⚠️ **ALERTA DE SPOOFING / REMETENTE FORJADO:** Houve divergência entre o remetente visível e o envelope real ou falha na validação SPF/DKIM/DMARC.")
            elif autenticacao_valida and alinhamento_valido:
                st.success(f"✅ **MENSAGEM AUTÊNTICA:** O remetente (`{remetente_dominio}`) e o envelope (`{return_path_dominio}`) pertencem ao mesmo domínio/organização e todas as assinaturas criptográficas (SPF, DKIM e DMARC) foram validadas com sucesso (PASS).")
            elif autenticacao_valida:
                st.success("✅ **AUTENTICAÇÃO APROVADA:** As assinaturas SPF, DKIM e DMARC foram validadas com sucesso (PASS).")
            else:
                st.info("ℹ️ Não foram encontradas divergências evidentes de identidade.")

        with tab_whois:
            st.subheader("Informações do Servidor de Origem e Provedores")
            col_ip1, col_ip2 = st.columns(2)
            with col_ip1:
                st.markdown("#### IP de Envio (Originating IP)")
                st.write(f"- **IP:** `{ip_origem}`")
                st.write(f"- **Organização / ISP:** `{ip_info.get('org', 'Desconhecido')}`")
                st.write(f"- **ASN:** `{ip_info.get('asn', 'Desconhecido')}`")
                st.write(f"- **País:** `{ip_info.get('country', 'Desconhecido')}`")
                st.write(f"- **Abuse E-mails:** `{', '.join(ip_info.get('abuse_emails', [])) or 'Não encontrado'}`")
            
            with col_ip2:
                st.markdown("#### Domínio do Remetente")
                st.write(f"- **Domínio:** `{remetente_dominio}`")
                st.write(f"- **Registrar:** `{remetente_whois.get('registrar', 'Desconhecido')}`")
                st.write(f"- **Abuse E-mails:** `{', '.join(remetente_whois.get('abuse_emails', [])) or 'Não encontrado'}`")

            if len(todos_ips) > 1:
                st.markdown("#### Todos os IPs Públicos Rastreados nos Saltos (Received):")
                for i, rip in enumerate(todos_ips, 1):
                    st.write(f"{i}. `{rip}`")

        with tab_links:
            st.subheader("URLs e Domínios Encontrados no Corpo da Mensagem")
            if links_detectados:
                for idx, l in enumerate(links_detectados, 1):
                    with st.container():
                        st.markdown(f"**Link #{idx}**")
                        if l["mismatched"]:
                            st.error(f"🚨 **Discrepância Detectada:** O texto dizia `{l['text']}`, mas o destino real é `{l['url']}`")
                        else:
                            st.markdown(f"- **Texto Âncora:** `{l['text']}`")
                        st.markdown(f"- **Destino Real:** `{l['url']}`")
                        st.markdown(f"- **Domínio:** `{l['domain']}`")
                        st.divider()
            else:
                st.info("Nenhuma URL externa encontrada no corpo da mensagem.")

        with tab_anexos:
            st.subheader("Arquivos Anexados")
            if anexos:
                for a in anexos:
                    with st.expander(f"📁 {a['filename']} ({a['size_kb']})", expanded=a['is_suspicious']):
                        if a['is_suspicious']:
                            st.error("⚠️ **Extensão potencialmente perigosa!**")
                        st.write(f"- **Tipo MIME:** `{a['content_type']}`")
                        st.write(f"- **Tamanho:** `{a['size_kb']}`")
                        st.write(f"- **SHA-256:** `{a['sha256']}`")
            else:
                st.info("Nenhum anexo encontrado nesta mensagem.")

        with tab_raw:
            st.subheader("Cabeçalhos Brutos da Mensagem (.eml)")
            raw_headers = "\n".join([f"{k}: {v}" for k, v in msg.items()])
            st.text_area("Cabeçalhos completos:", value=raw_headers, height=300)

    except Exception as e:
        st.error(f"Erro ao processar o arquivo .eml: {e}")
        st.exception(e)

