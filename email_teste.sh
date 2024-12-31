#!/bin/bash

# Solicita o nome do usuário
read -p "Digite o usuário: " USER

echo -e "Segue a lista de e-mail do usuário: \n"

# Lista os e-mails do usuário
EMAILS=$(uapi --user="$USER" Email list_pops | egrep "\s+email:" | awk '{print $2}')

if [ -z "$EMAILS" ]; then
    echo "Nenhum e-mail encontrado para o usuário $USER."
    exit 1
fi

echo "$EMAILS"
echo -e "\n"

# Solicita o e-mail a ser testado
read -p "Qual e-mail deseja testar: " EMAIL

# Verifica se o e-mail está na lista
if ! echo "$EMAILS" | grep -q "$EMAIL"; then
    echo "O e-mail $EMAIL não está na lista de e-mails do usuário $USER."
    exit 1
fi

# Envia um e-mail de teste
if echo "Olá, este é um teste." | mailx -r "$EMAIL" -s "Teste de E-mail" "hgbrasilteste@gmail.com"; then
    echo -e "Teste realizado com sucesso\n"
else
    echo "Falha ao enviar o e-mail de teste.\n"
    exit 1
fi