#!/bin/bash

read -p "Digite o domínio: " DOMINIO
read -p "Digite o nome de usuário: " USER

# Verifica se o domínio possui registros NS
NULO=$(host -t ns "$DOMINIO" | awk '{print $3, $4}' | sed 's/://g')
if [[ "$NULO" == "not found" ]]; then
    echo "Domínio não está Pingando"
    exit 1
fi

# Obtém registros DNS e MX
DNS=$(host -t ns "$DOMINIO" | awk '{print $4, $5}')
MX=$(host -t mx "$DOMINIO" | awk '{print $7}' | sed 's/\.$//')

echo "DNS: $DNS"
echo ""
echo "####################################################"
echo "MX: $MX"
echo ""
echo "####################################################"
echo ""

# Verifica se o MX é local
if [[ "$MX" == *"mail.$DOMINIO"* ]]; then
    echo "Apontamento ajustado para Local"
    uapi --user="$USER" Email set_always_accept domain="$DOMINIO" alwaysaccept=local
    
    # Variável para rastrear bloqueios
    bloqueio_detectado=0
    
    # Verifica bloqueios específicos
    CDRBL=$(grep "$DOMINIO" /var/log/exim_mainlog | grep "AUP#CDRBL")
    if [ -n "$CDRBL" ]; then
        echo "Você está com bloqueio de AUP#CDRBL"
        bloqueio_detectado=1
    else
        echo "Não há bloqueio de AUP#CDRBL"
    fi

    BL=$(grep "$DOMINIO" /var/log/exim_mainlog | grep "AUP#BL")
    BLS=$(grep "$DOMINIO" /var/log/exim_mainlog | grep "spamhaus.org")
    if [ -n "$BL" ]; then
        echo "O IP de sua rede está na blacklist da cloudmark, segue o link onde deve ser solicitado o Delist:"
        grep -o 'https://csi\.cloudmark\.com/en/reset?ip=[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+' /var/log/exim_mainlog | uniq
        bloqueio_detectado=1
    fi

    if [ -n "$BLS" ]; then
        echo "O IP de sua rede está listado no Spamhaus, segue o link onde deve ser solicitado o Delist:"
        grep -o 'http://www.spamhaus.org/query/ip/[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' /var/log/exim_mainlog | uniq
    fi

    SNDR=$(grep "$DOMINIO" /var/log/exim_mainlog | grep "AUP#SNDR")
    if [ -n "$SNDR" ]; then
        echo "O cliente está com bloqueio de AUP#SNDR"
        bloqueio_detectado=1
    else
        echo "Não há bloqueio de AUP#SNDR"
    fi

    # Novas verificações adicionadas
    BL_HOSTING=$(grep "$DOMINIO" /var/log/exim_mainlog | grep "blocklist_hosting")
    if [ -n "$BL_HOSTING" ]; then
        echo "O cliente está com bloqueio de blocklist_hosting"
        bloqueio_detectado=1
    fi

    POL=$(grep "$DOMINIO" /var/log/exim_mainlog | grep "AUP#POL")
    if [ -n "$POL" ]; then
        echo "O cliente está com bloqueio de AUP#POL"
        bloqueio_detectado=1
    fi

    # Mostra últimas 9 linhas do log se houver bloqueios
    if [ "$bloqueio_detectado" -eq 1 ]; then
        echo -e "\nExibindo últimas 9 linhas do /var/log/exim_mainlog:"
        tail -n 9 /var/log/exim_mainlog
    fi
else
    echo "Apontamento ajustado para Remoto"
    uapi --user="$USER" Email set_always_accept domain="$DOMINIO" alwaysaccept=remote
fi

# Executa scripts finais
/scripts/mailperm "$USER"
/scripts/remove_dovecot_index --user "$USER"