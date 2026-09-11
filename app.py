import streamlit as st
import email
from email import policy
from email.utils import parsedate_to_datetime
import re
from urllib.parse import urlparse
import whois  # <-- Nova biblioteca para buscar o Abuse

# Configuração da interface
st.set_page_config(page_title="Gerador de Denúncia de Phishing", page_icon="🎣")
st.title("🎣 Gerador de Denúncia de Phishing")
st.write("Faça o upload do arquivo `.eml` para extrair indicadores, descobrir contatos de abuse e gerar a denúncia.")

uploaded_file = st.file_uploader("Selecione o arquivo .eml", type=["eml"])

if uploaded_file is not None:
    try:
        raw_email = uploaded_file.read()
        msg = email.message_from_bytes(raw_email, policy=policy.default)
        
        # 1. Extrair o E-mail do Remetente
        sender_raw = msg.get("From", "")
        sender_match = re.search(r'<(.+?)>', sender_raw)
        sender_email = sender_match.group(1) if sender_match else sender_raw

        # 2. Extrair IP de Origem
        ip_origem = msg.get("X-SenderIP")
        if not ip_origem:
            ip_origem = "Não identificado"

        # 3. Formatar Data e Hora
        date_header = msg.get("Date")
        if date_header:
            dt = parsedate_to_datetime(date_header)
            data_hora = dt.strftime("%d/%m/%Y às %H:%M:%S") + f" ({dt.strftime('%z')})"
        else:
            data_hora = "Data não identificada"

        # 4. Extrair o corpo do e-mail
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type in ["text/plain", "text/html"]:
                    try:
                        body += part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
                    except:
                        pass
        else:
            body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8')
            
        # 5. Extrair Domínio Malicioso
        urls = re.findall(r'(https?://\S+)', body)
        clean_urls = list(set([re.sub(r'[\"\'>)]+$', '', url) for url in urls]))
        
        dominios = []
        for u in clean_urls:
            dominio = urlparse(u).netloc
            if dominio and dominio not in dominios:
                dominios.append(dominio)
        
        dominio_golpe = ", ".join(dominios) if dominios else "Nenhum link"

        # 6. BUSCA AUTOMÁTICA DE ABUSE (WHOIS)
        contatos_abuse = set()
        if dominios:
            with st.spinner('Consultando WHOIS para descobrir os e-mails de abuse...'):
                for dom in dominios:
                    try:
                        w = whois.whois(dom)
                        if w.emails:
                            # O whois pode retornar uma string ou uma lista de strings
                            emails_encontrados = w.emails if isinstance(w.emails, list) else [w.emails]
                            for e in emails_encontrados:
                                # Filtra apenas os e-mails que contenham a palavra 'abuse'
                                if 'abuse' in e.lower():
                                    contatos_abuse.add(e.lower())
                    except:
                        pass # Ignora se o domínio não existir ou der timeout
        
        texto_abuse = ", ".join(contatos_abuse) if contatos_abuse else "Nenhum e-mail de abuse encontrado automaticamente no WHOIS do domínio."

        # 7. Identificar o provedor para a saudação
        provedor = sender_email.split('@')[-1].split('.')[0].upper() if '@' in sender_email else "PROVEDOR"
        provedor_origem = sender_email.split('@')[-1] if '@' in sender_email else "provedor.com"

        # 8. MONTAR O TEXTO FINAL DA DENÚNCIA
        denuncia_texto = f"""Prezada equipe de segurança / Abuse {provedor},

Gostaria de denunciar o envio de e-mails maliciosos (phishing) originados a partir de uma conta do seu provedor.

* Conta remetente: {sender_email}
* IP de Origem: {ip_origem}
* Data/Hora: {data_hora}
* Domínio de destino do golpe: {dominio_golpe}

Tudo indica que a conta em questão foi comprometida e está sendo utilizada para disparos em massa. Solicito a verificação e o bloqueio da conta para conter o incidente."""

        # --- EXIBIR RESULTADOS NA TELA ---
        st.success("Análise concluída com sucesso!")
        
        # Destaca para quem enviar o e-mail
        st.subheader("🎯 Para quem enviar esta denúncia?")
        st.info(f"**Envie para o provedor do remetente:** abuse@{provedor_origem}")
        if contatos_abuse:
            st.warning(f"**Sugestão (Derrubar o site falso):** Coloque em cópia (CC) o provedor do domínio malicioso: `{texto_abuse}`")
        else:
            st.warning("**Derrubar o site falso:** Não foi possível achar o abuse do domínio malicioso automaticamente.")
        
        st.text_area("📋 Copie o texto abaixo para enviar sua denúncia:", value=denuncia_texto, height=300)
        
        # Aba de detalhes técnicos
        with st.expander("🛠️ Ver detalhes técnicos extraídos"):
            st.markdown(f"**Remetente Extraído:** `{sender_email}`")
            st.markdown(f"**Provedor Identificado:** `{provedor}`")
            st.markdown(f"**Domínio do Golpe:** `{dominio_golpe}`")
            st.markdown("**URLs Completas Encontradas no Corpo:**")
            if clean_urls:
                for u in clean_urls:
                    st.code(u)
            else:
                st.write("Nenhuma URL detectada.")

    except Exception as e:
        st.error(f"Ocorreu um erro ao processar o arquivo: {e}")
