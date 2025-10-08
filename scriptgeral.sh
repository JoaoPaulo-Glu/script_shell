#!/bin/bash

# Cores para output
RED='\033[1;31m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
GREEN='\033[1;32m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
NC='\033[0m' # Sem cor

# Constantes para formatação
ETER=1
ECAB=2

# Função para formatação de output (similar à _echoFormat)
_echoFormat() {
    local message="$1"
    local length="$2"
    local color="${3:-$NC}"
    
    # Calcula padding
    local total_length=60
    local message_length=${#message}
    local padding=$(( (total_length - message_length) / 2 ))
    
    printf "${color}"
    printf "=%.0s" $(seq 1 $padding)
    printf "%s" "$message"
    printf "=%.0s" $(seq 1 $padding)
    printf "${NC}\n"
}

# Função para validar usuário reservado
_check_user(){
    local _usr="$1"
    local _silent="${2:-0}"
    
    if [[ "${_usr}" == "root" ]] || [[ ${_usr} == "hgdummy" ]] || [[ ${_usr} == "hgtransf" ]] || \
       [[ ${_usr} == "eig1wp11" ]] || [[ ${_usr} == "hgtransfer" ]]; then
        [[ "${_silent}" -eq 1 ]] || echo -e "\n${RED}[X]${NC} O usuário ${_usr}, é um usuário reservado e não pode ser utilizado para executar essa verificação.\n"
        return 1
    else    
        [[ "${_silent}" -eq 1 ]] || echo -e "\n${YELLOW}[?]${NC} Validando usuário..."
        [[ "${_silent}" -eq 1 ]] || echo -e "\t${GREEN}[!]${NC} Usuário válido."
        return 0
    fi
}

# Função para validar servidor LATAM
_validaServer(){
    local tlds=("mx cl co br")
    local tmp_verif="/tmp/valida_server_$$"
    local MESINFO="[INFO]"
    local MESERRO="[ERRO]"
    
    mkdir -p "$tmp_verif"
    
    _echoFormat " Validações Iniciais " "$( expr $ETER + $ECAB)" "${YELLOW}"
    
    if [[ $(hostname) =~ .*hostgator* ]] || [[ $(hostname) =~ .*prodns*  ]] && [[ -e /opt/hgctrl/.zengator ]]; then
        _echoFormat "${MESINFO} Servidor Compartilhado LATAM\n" "$( expr $ETER)" "${GREEN}"
        rm -rf "$tmp_verif"
        return 0
    elif [[ ! -z $(grep -w "$(wget -qO "$tmp_verif/brand" http://custapi.unifiedlayer.com/servbrand ; cat "$tmp_verif/brand" | awk -F'_' '{print $NF}')" <<< $tlds ) ]] ; then
        _echoFormat "${MESINFO} Servidor VPS/Dedi LATAM\n" "$( expr $ETER)" "${GREEN}"
        rm -rf "$tmp_verif"
        return 0
    else 
        _echoFormat "${MESERRO} Este não é um servidor LATAM\n" "$( expr $ETER)" "${RED}"
        rm -rf "$tmp_verif"
        return 1
    fi
}

# Função para mostrar sistema operacional
show_os() {
    echo "=== SISTEMA OPERACIONAL ==="
    
    if [[ -f "/etc/os-release" ]]; then
        local os_name
        os_name=$(grep ^PRETTY_NAME /etc/os-release | cut -d= -f2- | tr -d '"')
        echo -e "${GREEN}Sistema Operacional:${NC} $os_name"
    else
        echo -e "${YELLOW}Arquivo /etc/os-release não encontrado${NC}"
        
        # Tentativas alternativas
        if [[ -f "/etc/redhat-release" ]]; then
            echo -e "${GREEN}Distribuição:${NC} $(cat /etc/redhat-release)"
        elif [[ -f "/etc/issue" ]]; then
            echo -e "${GREEN}Distribuição:${NC} $(cat /etc/issue | head -1)"
        fi
    fi
    
    echo -e "${GREEN}Kernel:${NC} $(uname -r)"
    echo -e "${GREEN}Arquitetura:${NC} $(uname -m)"
    echo -e "${GREEN}Hostname:${NC} $(hostname)"
    
    # Informações adicionais úteis
    echo ""
    echo "=== INFORMAÇÕES ADICIONAIS ==="
    if command -v lsb_release &> /dev/null; then
        echo -e "${GREEN}LSB Release:${NC} $(lsb_release -d | cut -f2)"
    fi
    
    if command -v uptime &> /dev/null; then
        echo -e "${GREEN}Uptime:${NC} $(uptime -p | sed 's/up //')"
    fi
}

# Função de ajuda
show_help() {
    echo "Uso: $0 [OPÇÕES]"
    echo ""
    echo "Opções:"
    echo "  --inodes USER DIRETORIO    Lista os INODES do diretório do usuário"
    echo "  --disk USER DIRETORIO      Mostra o espaço em disco do diretório"
    echo "  --mail DOMINIO             Verifica e ajusta configurações MX"
    echo "  --webmail USER             Ajusta interface do webmail para padrão"
    echo "  --titan USER               Ajusta interface do webmail para Titan"
    echo "  --500_webmail USER         Corrige erro 404/500 no webmail"
    echo "  --backup_infect USER DIR   Verifica backups por malwares"
    echo "  --excludemsg CONTA         Mostra logs de exclusão de mensagens"
    echo "  --so                       Mostra informações do sistema operacional"
    echo "  -h, --help                 Mostra esta ajuda"
    echo ""
    echo "Exemplos:"
    echo "  $0 --inodes joao Documentos"
    echo "  $0 --disk maria Downloads"
    echo "  $0 --mail meudominio.com"
    echo "  $0 --webmail joao"
    echo "  $0 --titan maria"
    echo "  $0 --500_webmail joao"
    echo "  $0 --backup_infect joao public_html"
    echo "  $0 --excludemsg conta@dominio.com"
    echo "  $0 --so"
    exit 0
}

# Função para obter o diretório home do usuário
get_user_home() {
    local user="$1"
    local home_dir
    
    home_dir=$(grep "^$user:" /etc/passwd | cut -d: -f6)
    
    if [[ -z "$home_dir" ]]; then
        echo "Erro: Usuário '$user' não encontrado!" >&2
        return 1
    fi
    
    if [[ ! -d "$home_dir" ]]; then
        echo "Erro: Diretório home do usuário '$user' não existe!" >&2
        return 1
    fi
    
    echo "$home_dir"
    return 0
}

# Função para listar INODES
list_inodes() {
    local user="$1"
    local directory="$2"
    local home_dir
    local target_path
    
    # Valida usuário
    if ! _check_user "$user"; then
        exit 1
    fi
    
    home_dir=$(get_user_home "$user")
    if [[ $? -ne 0 ]]; then
        exit 1
    fi
    
    target_path="$home_dir/$directory"
    
    if [[ ! -d "$target_path" ]]; then
        echo "Erro: Diretório '$target_path' não existe!" >&2
        exit 1
    fi
    
    echo "=== INODES do diretório: $target_path ==="
    echo "Usuário: $user"
    echo "Diretório: $directory"
    echo "Total de inodes: $(find "$target_path" | wc -l)"
    echo ""
    
    # Lista detalhada dos inodes
    echo "Lista detalhada:"
    if command -v ls >/dev/null 2>&1; then
        ls -ial "$target_path"
    else
        find "$target_path" -printf "%i %p\n" | head -20
        echo "... (primeiros 20 itens)"
    fi
}

# Função para verificar espaço em disco
show_disk_usage() {
    local user="$1"
    local directory="$2"
    local home_dir
    local target_path
    
    # Valida usuário
    if ! _check_user "$user"; then
        exit 1
    fi
    
    home_dir=$(get_user_home "$user")
    if [[ $? -ne 0 ]]; then
        exit 1
    fi
    
    target_path="$home_dir/$directory"
    
    if [[ ! -d "$target_path" ]]; then
        echo "Erro: Diretório '$target_path' não existe!" >&2
        exit 1
    fi
    
    echo "=== ESPAÇO EM DISCO: $target_path ==="
    echo "Usuário: $user"
    echo "Diretório: $directory"
    echo ""
    
    # Verifica espaço em disco
    if command -v du >/dev/null 2>&1; then
        echo "Uso de disco:"
        du -sh "$target_path"
        echo ""
        echo "Detalhamento por subdiretórios (top 10):"
        du -sh "$target_path"/* 2>/dev/null | sort -hr | head -10
    else
        echo "Comando 'du' não disponível. Instale o pacote 'coreutils'."
    fi
    
    # Verifica espaço livre no filesystem
    echo ""
    echo "Espaço livre no filesystem:"
    df -h "$target_path" | tail -1
}

# Função para verificar e ajustar configurações MX
check_mx() {
    local dominio="$1"
    
    echo "=== VERIFICAÇÃO MX: $dominio ==="
    
    # Verifica se o domínio existe no DNS
    if host -t mx "$dominio" 2>&1 | grep -q 'not found'; then
        echo "Erro: Domínio '$dominio' sem MX ou não ativo"
        return 1
    fi
    
    # Obtém os registros MX
    local mx_records
    mx_records=$(host -t mx "$dominio" | awk '{print $7}' | sed 's/\.$//')
    
    echo "Registros MX encontrados:"
    echo "$mx_records"
    echo ""
    
    # Obtém o usuário do domínio
    local user
    user=$(grep "$dominio" /etc/userdomains 2>/dev/null | awk '{print $2}' | uniq)
    
    if [[ -z "$user" ]]; then
        echo "Erro: Domínio '$dominio' não encontrado em /etc/userdomains"
        return 1
    fi
    
    # Valida usuário
    if ! _check_user "$user" 1; then
        echo -e "\n${RED}[X]${NC} O usuário ${user} é reservado. Operação cancelada.\n"
        return 1
    fi
    
    echo "Usuário responsável: $user"
    echo ""
    
    # Verifica se o MX aponta para o próprio servidor
    local local_mx=false
    for mx in $mx_records; do
        if [[ "$mx" == "mail.$dominio" ]] || [[ "$mx" == "$dominio" ]]; then
            local_mx=true
            break
        fi
    done
    
    if [[ "$local_mx" == true ]]; then
        echo "Apontamento ajustado para LOCAL"
        
        # Ajusta para aceitar local
        uapi --user="$user" Email set_always_accept domain="$dominio" alwaysaccept=local > /dev/null 2>&1
        
        # Ajusta permissões e renova dovecot
        echo "Ajustando permissões das caixas de e-mail..."
        /scripts/mailperm "$user" > /dev/null 2>&1
        
        echo "Renovando índices do Dovecot..."
        /scripts/remove_dovecot_index_files --user "$user" > /dev/null 2>&1
        
        echo "Configurações locais aplicadas com sucesso!"
    else
        echo "Apontamento ajustado para REMOTO"
        
        # Ajusta para aceitar remoto
        uapi --user="$user" Email set_always_accept domain="$dominio" alwaysaccept=remote > /dev/null 2>&1
        
        echo "Configurações remotas aplicadas com sucesso!"
    fi
}

# Função para ajustar interface do webmail padrão
setup_webmail() {
    local user="$1"
    
    # Valida usuário
    if ! _check_user "$user"; then
        exit 1
    fi
    
    echo "=== AJUSTANDO WEBMAIL PADRÃO: $user ==="
    
    # Verifica se o usuário existe
    if ! get_user_home "$user" > /dev/null 2>&1; then
        echo "Erro: Usuário '$user' não encontrado!"
        exit 1
    fi
    
    # Ajusta configurações via UAPI
    uapi --user="$user" NVData set names="fm_setup" fm_setup=0 > /dev/null 2>&1
    uapi --user="$user" NVData set names="fm_local" fm_local=1 > /dev/null 2>&1
    
    # Obtém o diretório home e renomeia datastore
    local home_dir
    home_dir=$(get_user_home "$user")
    
    local datastore_path="$home_dir/.cpanel/datastore"
    local backup_path="$home_dir/.cpanel/datastore_backup"
    
    if [[ -d "$datastore_path" ]]; then
        mv "$datastore_path" "$backup_path" 2>/dev/null
        echo "Datastore movido: $datastore_path -> $backup_path"
    else
        echo "Datastore não encontrado em: $datastore_path"
    fi
    
    echo "Webmail ajustado para interface padrão com sucesso!"
}

# Função para ajustar interface do webmail Titan
setup_titan() {
    local user="$1"
    
    # Valida usuário
    if ! _check_user "$user"; then
        exit 1
    fi
    
    echo "=== AJUSTANDO WEBMAIL TITAN: $user ==="
    
    # Verifica se o usuário existe
    if ! get_user_home "$user" > /dev/null 2>&1; then
        echo "Erro: Usuário '$user' não encontrado!"
        exit 1
    fi
    
    # Ajusta configurações via UAPI
    uapi --user="$user" NVData set names="fm_setup" fm_setup=0 > /dev/null 2>&1
    uapi --user="$user" NVData set names="fm_local" fm_local=0 > /dev/null 2>&1
    
    # Obtém o diretório home e renomeia datastore
    local home_dir
    home_dir=$(get_user_home "$user")
    
    local datastore_path="$home_dir/.cpanel/datastore"
    local backup_path="$home_dir/.cpanel/datastore_backup"
    
    if [[ -d "$datastore_path" ]]; then
        mv "$datastore_path" "$backup_path" 2>/dev/null
        echo "Datastore movido: $datastore_path -> $backup_path"
    else
        echo "Datastore não encontrado em: $datastore_path"
    fi
    
    echo "Webmail ajustado para Titan com sucesso!"
}

# Função para corrigir erro 404/500 no webmail
fix_webmail_error() {
    local user="$1"
    
    # Valida usuário
    if ! _check_user "$user"; then
        exit 1
    fi
    
    echo "=== CORRIGINDO ERRO 404/500 WEBMAIL: $user ==="
    
    # Verifica se o usuário existe
    if ! get_user_home "$user" > /dev/null 2>&1; then
        echo "Erro: Usuário '$user' não encontrado!"
        exit 1
    fi
    
    # Executa os comandos de correção
    echo "Removendo cache..."
    /opt/eig_linux/bin/caching_cli.pl --user "$user" --remove --all -v
    
    echo "Reiniciando Apache..."
    httpd -k graceful
    
    echo "Correção aplicada! Pode ser necessário rodar mais de uma vez."
    echo "Recomendação: Verifique se o erro persiste após alguns minutos."
}

# Função para verificar backups infectados
check_backup_infect() {
    local user="$1"
    local directory="$2"
    
    # Valida usuário
    if ! _check_user "$user"; then
        exit 1
    fi
    
    echo "=== VERIFICANDO BACKUPS POR MALWARES: $user ==="
    
    # Verificar se o usuário existe no /etc/userdomains
    if ! grep -qE "[[:space:]]+${user}$" /etc/userdomains 2>/dev/null; then
        echo -e "${RED}Erro: Usuário '$user' não identificado em /etc/userdomains${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Usuário identificado: $user${NC}"
    echo "Diretório a verificar: $directory"
    echo ""
    
    # Pegar lista de arquivos suspeitos
    echo "Gerando lista de arquivos suspeitos..."
    SUSPECTS=$(mktemp)
    HOMEDIR=$(get_user_home "$user")
    
    if [[ $? -ne 0 ]] || [[ ! -d "$HOMEDIR" ]]; then
        echo -e "${RED}Erro: Não foi possível acessar o homedir do usuário${NC}"
        rm -f "$SUSPECTS"
        exit 1
    fi
    
    # Lista completa de padrões maliciosos
    find "$HOMEDIR" -type f \( \
        -iname "*.php" -o -iname "*.ico" -o -iname "*.inc" -o -iname "*.js.php" \
        -o -iname "*.ott" -o -iname "*.otc" -o -iname "*.oti" -o -iname "*.ccss" \
        -o -iname "*.hph" -o -iname "*shedit.set" -o -iname "*.mo" -o -iname "*.zip" \
    \) 2>/dev/null | grep -E \
    -e "/[0-9a-zA-Z]{8,10}\.php" \
    -e "admin\.php" -e "about\.php" -e "text\.php" -e "credits\.php" \
    -e "input\.php" -e "network\.php" -e "output\.php" -e "module\.php" \
    -e "style\.php" -e "top\.php" -e "shop\.php" -e "shops\.php" -e "options\.php" \
    -e "123\.php" -e "chtmlfuns\.php" -e "lowpr\.php" -e "xinder\.php" -e "good\.php" \
    -e "makeasmtp\.php" -e "groupon\.php" -e "cyborg_tmp\.php" -e "index2\.php" \
    -e "0x\.php" -e "admin-ajax\.php" -e "alfanew\.php" -e "xxx\.php" \
    -e "\.js\.php$" -e "shedit\.set$" -e "\.hph$" -e "\.ccss$" \
    -e "n3JaKCgNQu2xUIGN\.php" -e "upl\.php" -e "zpanel-v2\.0\.zip" \
    -e "/\.[A-Za-z0-9]{8}\.mo" -e "/\.[A-Za-z0-9]{8}\.inc" -e "/\.[A-Za-z0-9]{8}\.otc" \
    -e "/\.[A-Za-z0-9]{8}\.ico" -e "/\.[A-Za-z0-9]{8}\.ccss" -e "/\.[A-Za-z0-9]{8}\.ott" \
    -e "/\.[A-Za-z0-9]{8}\.oti" \
    > "$SUSPECTS" 2>/dev/null
    
    # Verificar se sshrestore existe
    if ! command -v sshrestore &> /dev/null; then
        echo -e "${RED}Erro: Comando 'sshrestore' não encontrado${NC}"
        rm -f "$SUSPECTS"
        exit 1
    fi
    
    # Pegar lista de backups
    echo "Obtendo lista de backups..."
    b=($(sshrestore -u "${user}" -l 2>/dev/null | grep \/back | awk -F: '{print$1}'))
    
    if [[ ${#b[@]} -eq 0 ]]; then
        echo -e "${YELLOW}Nenhum backup encontrado para o usuário $user${NC}"
        rm -f "$SUSPECTS"
        return 0
    fi
    
    echo -e "${GREEN}Encontrados ${#b[@]} backups${NC}"
    echo ""
    
    # Listar arquivos do caminho nos backups
    local found_suspects=0
    for dt in "${b[@]}"; do
        echo -e "\n${YELLOW}=== Backup: $dt ===${NC}"
        backup_path="${dt}/homedir/${directory}"
        
        if [[ -d "$backup_path" ]]; then
            while IFS= read -r entry; do
                if [[ -n "$entry" ]]; then
                    full_path="${backup_path}/${entry}"
                    if [[ -d "$full_path" ]]; then
                        echo -e "${BLUE}[DIR] ${entry}${NC}"
                    else
                        # Verificar se o arquivo está na lista de suspeitos
                        if grep -Fxq "$HOMEDIR/${directory}/$entry" "$SUSPECTS" 2>/dev/null; then
                            echo -e "${RED}[MALWARE SUSPEITO] ${entry}${NC}"
                            found_suspects=1
                        else
                            echo "[OK] $entry"
                        fi
                    fi
                fi
            done < <(ls -1 "$backup_path" 2>/dev/null)
        else
            echo -e "${YELLOW}(caminho não encontrado neste backup)${NC}"
        fi
    done
    
    if [[ $found_suspects -eq 1 ]]; then
        echo -e "\n${RED}ATENÇÃO: Foram encontrados arquivos suspeitos nos backups!${NC}"
        echo "Recomenda-se verificação manual e limpeza."
    else
        echo -e "\n${GREEN}Nenhum arquivo suspeito encontrado nos backups verificados.${NC}"
    fi
    
    # Limpar arquivo temporário
    rm -f "$SUSPECTS"
}

# Função para mostrar logs de exclusão de mensagens
show_exclude_msg() {
    local conta="$1"
    
    echo "=== LOGS DE EXCLUSÃO DE MENSAGENS: $conta ==="
    echo ""
    
    if [[ ! -f "/var/log/maillog" ]]; then
        echo -e "${RED}Erro: Arquivo /var/log/maillog não encontrado${NC}"
        exit 1
    fi
    
    # Verificar permissões
    if [[ ! -r "/var/log/maillog" ]]; then
        echo -e "${RED}Erro: Sem permissão para ler /var/log/maillog${NC}"
        exit 1
    fi
    
    echo "Buscando logs de exclusão para: $conta"
    echo "---"
    
    grep "$conta" /var/log/maillog | egrep -v 'deleted=0|del=0' | egrep -i 'del=|deleted='
    
    local count=$(grep "$conta" /var/log/maillog 2>/dev/null | egrep -v 'deleted=0|del=0' | egrep -i 'del=|deleted=' | wc -l)
    
    echo "---"
    echo -e "${GREEN}Total de entradas encontradas: $count${NC}"
}

# Processamento dos argumentos
main() {
    # Validação do servidor - descomente a linha abaixo se quiser forçar validação
    # if ! _validaServer; then
    #     exit 1
    # fi
    
    case "$1" in
        -h|--help)
            show_help
            ;;
        --so)
            show_os
            ;;
        --inodes)
            if [[ $# -ne 3 ]]; then
                echo "Erro: --inodes requer USER e DIRETORIO" >&2
                echo "Use: $0 --inodes USER DIRETORIO" >&2
                exit 1
            fi
            list_inodes "$2" "$3"
            ;;
        --disk)
            if [[ $# -ne 3 ]]; then
                echo "Erro: --disk requer USER e DIRETORIO" >&2
                echo "Use: $0 --disk USER DIRETORIO" >&2
                exit 1
            fi
            show_disk_usage "$2" "$3"
            ;;
        --mail)
            if [[ $# -ne 2 ]]; then
                echo "Erro: --mail requer DOMINIO" >&2
                echo "Use: $0 --mail DOMINIO" >&2
                exit 1
            fi
            check_mx "$2"
            ;;
        --webmail)
            if [[ $# -ne 2 ]]; then
                echo "Erro: --webmail requer USER" >&2
                echo "Use: $0 --webmail USER" >&2
                exit 1
            fi
            setup_webmail "$2"
            ;;
        --titan)
            if [[ $# -ne 2 ]]; then
                echo "Erro: --titan requer USER" >&2
                echo "Use: $0 --titan USER" >&2
                exit 1
            fi
            setup_titan "$2"
            ;;
        --500_webmail)
            if [[ $# -ne 2 ]]; then
                echo "Erro: --500_webmail requer USER" >&2
                echo "Use: $0 --500_webmail USER" >&2
                exit 1
            fi
            fix_webmail_error "$2"
            ;;
        --backup_infect)
            if [[ $# -ne 3 ]]; then
                echo "Erro: --backup_infect requer USER e DIRETORIO" >&2
                echo "Use: $0 --backup_infect USER DIRETORIO" >&2
                exit 1
            fi
            check_backup_infect "$2" "$3"
            ;;
        --excludemsg)
            if [[ $# -ne 2 ]]; then
                echo "Erro: --excludemsg requer CONTA" >&2
                echo "Use: $0 --excludemsg CONTA" >&2
                exit 1
            fi
            show_exclude_msg "$2"
            ;;
        *)
            echo "Erro: Opção desconhecida '$1'" >&2
            echo "Use: $0 --help para ver as opções disponíveis" >&2
            exit 1
            ;;
    esac
}

# Verifica se há argumentos
if [[ $# -eq 0 ]]; then
    echo "Erro: Nenhum argumento fornecido" >&2
    show_help
fi

# Executa a função principal
main "$@"
