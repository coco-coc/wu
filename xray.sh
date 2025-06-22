#!/bin/bash

# 全局颜色定义
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
CYAN="\033[36m"
NC="\033[0m"

# 信息前缀
INFO="${GREEN}[信息]${NC}"
ERROR="${RED}[错误]${NC}"
WARNING="${YELLOW}[警告]${NC}"

# 检测系统类型
detect_os() {
    if [ -f /etc/alpine-release ]; then
        echo "alpine"
    elif grep -q "Ubuntu" /etc/os-release; then
        echo "ubuntu"
    elif grep -q "Debian" /etc/os-release; then
        echo "debian"
    elif grep -q "CentOS" /etc/os-release || grep -q "Red Hat" /etc/os-release || grep -q "AlmaLinux" /etc/os-release; then
        echo "centos"
    else
        echo "unknown"
    fi
}

OS_TYPE=$(detect_os)

# 颜色输出函数
red() { echo -e "${RED}$1${NC}"; }
green() { echo -e "${GREEN}$1${NC}"; }
yellow() { echo -e "${YELLOW}$1${NC}"; }
blue() { echo -e "${BLUE}$1${NC}"; }
cyan() { echo -e "${CYAN}$1${NC}"; }

# ============================== Xray 安装部分 ==============================
install_xray() {
    # 清理旧日志
    rm -f /var/log/xray*.log

    yellow "检测系统类型：$OS_TYPE"
    yellow "开始安装依赖..."
    install_deps
    
    # 选择协议
    yellow "请选择协议："
    select protocol in "vmess" "trojan" "vless" "shadowsocks"; do
        PROTOCOL=$protocol
        break
    done
    
    # 输入域名和路径（Shadowsocks不需要）
    if [[ "$PROTOCOL" != "shadowsocks" ]]; then
        read -p "请输入域名（已解析到本机IP）：" DOMAIN
        read -p "请输入WebSocket路径（默认/）：" WS_PATH
        [[ -z "$WS_PATH" ]] && WS_PATH="/"
    else
        # Shadowsocks不需要域名和路径
        DOMAIN=""
        WS_PATH=""
    fi
    
    # 配置证书（Shadowsocks不需要证书）
    if [[ "$PROTOCOL" != "shadowsocks" ]]; then
        setup_certificates
    fi
    
    # 生成认证信息
    if [[ "$PROTOCOL" == "trojan" ]]; then
        read -p "请输入Trojan密码（默认随机生成）：" PASSWORD
        [[ -z "$PASSWORD" ]] && PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
        green "Trojan 密码已生成：$PASSWORD"
        TROJAN_PASSWORD="$PASSWORD"  # 保存密码变量
    elif [[ "$PROTOCOL" == "shadowsocks" ]]; then
        read -p "请输入Shadowsocks密码（默认随机生成）：" PASSWORD
        [[ -z "$PASSWORD" ]] && PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
        green "Shadowsocks 密码已生成：$PASSWORD"
        
        yellow "请选择加密方式："
        select method in "aes-256-gcm" "chacha20-poly1305" "aes-128-gcm" "none"; do
            SS_METHOD=$method
            break
        done
        [[ "$SS_METHOD" == "none" ]] && SS_METHOD="plain"
    else
        UUID=$(cat /proc/sys/kernel/random/uuid)
        green "UUID 已生成：$UUID"
    fi
    
    # 端口配置
    read -p "请输入监听端口（默认443）：" IN_PORT
    [[ -z "$IN_PORT" ]] && IN_PORT=443
    if [[ "$IN_PORT" != "443" ]] && [[ "$PROTOCOL" != "shadowsocks" ]]; then
        yellow "建议使用443端口以提高兼容性"
    fi
    
    # 检查是否已安装 Xray
    if [[ ! -f "/root/Xray/xray" ]]; then
        # 使用 GitHub 官方源下载 Xray
        echo "正在从 GitHub 下载最新版 Xray..."
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) ARCH="64" ;;
            aarch64) ARCH="arm64-v8a" ;;
            armv7l) ARCH="arm32-v7a" ;;
            *) red "不支持的系统架构: $ARCH"; exit 1 ;;
        esac
        
        # 直接下载最新版
        DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${ARCH}.zip"
        LATEST_FILE="Xray-linux-${ARCH}.zip"
        
        echo "下载链接: $DOWNLOAD_URL"
        if ! wget -O "$LATEST_FILE" "$DOWNLOAD_URL"; then
            red "Xray 下载失败，请检查网络连接"
            exit 1
        fi
        
        # 解压到目标目录
        mkdir -p /root/Xray
        unzip -o -d /root/Xray "$LATEST_FILE"
        
        if [[ -f "/root/Xray/xray" ]]; then
            chmod +x /root/Xray/xray
            green "Xray 安装成功！"
            rm -f "$LATEST_FILE"
        else
            red "解压后未找到 xray 可执行文件"
            exit 1
        fi
    fi
    
    # 生成配置文件
    generate_config
    
    # 配置服务
    setup_service
    
    # 保存iptables规则
    if [[ "$OS_TYPE" == "centos" ]]; then
        # CentOS 需要安装iptables-services
        if ! rpm -q iptables-services >/dev/null; then
            yum install -y iptables-services
        fi
        systemctl enable iptables
        service iptables save
    elif [[ "$OS_TYPE" != "alpine" ]]; then
        iptables-save > /etc/iptables/rules.v4
    else
        iptables-save > /etc/iptables/rules
    fi
    
    # 生成客户端链接
    generate_links
    
    # 显示日志路径
    yellow "访问日志：/var/log/xray-access.log"
    yellow "错误日志：/var/log/xray-error.log"
    green "Xray 服务配置完成！"
    
    # 暂停以便用户查看链接
    echo ""
    read -p "按回车键返回主菜单..."
}

# Xray依赖安装（带检测）
install_deps() {
    case "$OS_TYPE" in
        "alpine")
            apk update
            # 定义依赖列表
            DEPS="curl wget unzip iptables nc-openbsd openrc openssl"
            for pkg in $DEPS; do
                if ! apk info -e $pkg &>/dev/null; then
                    yellow "安装 $pkg..."
                    apk add $pkg
                else
                    green "$pkg 已安装"
                fi
            done
            ;;
        "debian"|"ubuntu")
            apt update
            # 定义依赖列表
            DEPS="curl wget unzip netcat-openbsd iptables iptables-persistent openssl"
            for pkg in $DEPS; do
                if ! dpkg -s $pkg &>/dev/null; then
                    yellow "安装 $pkg..."
                    apt install -y $pkg
                else
                    green "$pkg 已安装"
                fi
            done
            ;;
        "centos")
            # CentOS 7 镜像源修复
            if grep -q "CentOS Linux 7" /etc/os-release; then
                echo "修复 CentOS 7 镜像源..."
                sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
                sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
                yum clean all
            fi
            
            # 安装EPEL仓库
            if ! rpm -q epel-release >/dev/null; then
                yellow "安装EPEL仓库..."
                yum install -y epel-release
            fi
            
            # 定义依赖列表
            DEPS="curl wget unzip nc iptables-services openssl"
            for pkg in $DEPS; do
                if ! rpm -q $pkg >/dev/null; then
                    yellow "安装 $pkg..."
                    yum install -y $pkg
                else
                    green "$pkg 已安装"
                fi
            done
            ;;
        *)
            red "不支持的系统类型！"
            exit 1
            ;;
    esac
}

# Xray服务管理配置
setup_service() {
    case "$OS_TYPE" in
        "alpine")
            cat << EOF > /etc/init.d/xray
#!/sbin/openrc-run
name="xray"
description="Xray Service"
command="/root/Xray/xray"
command_args="-config /root/Xray/config.json"
pidfile="/run/xray.pid"
respawn_delay=5
rc_ulimit="-n 30000"
output_log="/var/log/xray.log"
error_log="/var/log/xray.error.log"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath -f \$output_log -m 0644
    checkpath -f \$error_log -m 0644
}

start() {
    ebegin "Starting xray service"
    # Alpine系统使用不同的start-stop-daemon语法
    start-stop-daemon --start \
        --exec \$command \
        --pidfile \$pidfile \
        --background \
        --make-pidfile \
        -- \
        \$command_args
    eend \$?
}

stop() {
    ebegin "Stopping xray service"
    start-stop-daemon --stop \
        --exec \$command \
        --pidfile \$pidfile
    eend \$?
}
EOF
            chmod +x /etc/init.d/xray
            mkdir -p /var/log
            touch /var/log/xray.log
            rc-update add xray default
            service xray restart
            ;;
        "debian"|"ubuntu"|"centos")
            cat << EOF > /etc/systemd/system/xray.service
[Unit]
Description=Xray Service
After=network.target

[Service]
ExecStart=/root/Xray/xray -config /root/Xray/config.json
Restart=always
User=root
LimitNOFILE=30000
StandardOutput=file:/var/log/xray.log
StandardError=file:/var/log/xray-error.log

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable xray
            systemctl restart xray
            ;;
    esac
}

# Xray证书配置 - 增强验证逻辑（文件路径和手动输入）
setup_certificates() {
    read -p "请选择：1.已上传证书文件，输入证书路径；2.未上传证书，直接输入证书内容.(默认选择1)： " is_path
    [[ -z $is_path ]] && is_path=1
    
    if [[ $is_path == 1 ]]; then
        # 文件路径模式 - 添加循环验证
        while true; do
            read -p "请输入.crt结尾的证书绝对路径：" cert
            until [[ -f "$cert" ]]; do
                red "找不到文件！请检查输入路径！"
                read -p "请输入.crt结尾的证书绝对路径：" cert
            done
            
            read -p "请输入.key结尾的证书绝对路径：" key
            until [[ -f "$key" ]]; do
                red "找不到文件！请检查输入路径！"
                read -p "请输入.key结尾的证书绝对路径：" key
            done
            
            CERT_PATH="$cert"
            KEY_PATH="$key"
            
            # 验证证书匹配性
            cert_md5=$(openssl x509 -noout -modulus -in "$CERT_PATH" 2>/dev/null | openssl md5 | cut -d' ' -f2)
            key_md5=$(openssl rsa -noout -modulus -in "$KEY_PATH" 2>/dev/null | openssl md5 | cut -d' ' -f2)
            
            if [[ "$cert_md5" == "$key_md5" ]]; then
                green "√ 证书验证通过"
                break
            else
                red "证书与私钥不匹配！请检查文件内容是否正确"
                yellow "请重新输入证书路径..."
            fi
        done
    else
        # 手动输入模式 - 保持原有循环验证
        mkdir -p /root/Xray
        chmod 700 /root/Xray
        
        while true; do
            # 输入证书内容
            yellow "请输入证书内容（输入空行结束）："
            cert_txt=""
            while IFS= read -r line; do
                if [[ -z "$line" ]]; then
                    break
                fi
                cert_txt+="$line\n"
            done
            echo -e "$cert_txt" | sed '/^$/d' > /root/Xray/domain.crt
            yellow "证书被保存在：/root/Xray/domain.crt"
            
            # 输入私钥内容
            yellow "请输入对应的key内容（输入空行结束）："
            key_txt=""
            while IFS= read -r line; do
                if [[ -z "$line" ]]; then
                    break
                fi
                key_txt+="$line\n"
            done
            echo -e "$key_txt" | sed '/^$/d' > /root/Xray/domain.key
            yellow "私钥被保存在：/root/Xray/domain.key"
            
            CERT_PATH="/root/Xray/domain.crt"
            KEY_PATH="/root/Xray/domain.key"
            
            # 验证证书匹配性
            cert_md5=$(openssl x509 -noout -modulus -in "$CERT_PATH" 2>/dev/null | openssl md5 | cut -d' ' -f2)
            key_md5=$(openssl rsa -noout -modulus -in "$KEY_PATH" 2>/dev/null | openssl md5 | cut -d' ' -f2)
            
            if [[ "$cert_md5" == "$key_md5" ]]; then
                green "√ 证书验证通过"
                break
            else
                red "证书与私钥不匹配！请重新输入"
                # 删除无效证书文件
                rm -f /root/Xray/domain.crt /root/Xray/domain.key
                yellow "请重新输入证书内容..."
            fi
        done
    fi
}

# Xray生成协议配置
generate_config() {
    case "$PROTOCOL" in
        "vmess")
            CLIENT_CONFIG="\"id\": \"$UUID\", \"alterId\": 0, \"security\": \"auto\""
            TLS_SETTINGS="\"tlsSettings\": {
                \"certificates\": [{
                    \"certificateFile\": \"$CERT_PATH\",
                    \"keyFile\": \"$KEY_PATH\"
                }],
                \"alpn\": [\"http/1.1\"],
                \"serverName\": \"$DOMAIN\"
            }"
            ;;
        "trojan")
            CLIENT_CONFIG="\"password\": \"$TROJAN_PASSWORD\""
            TLS_SETTINGS="\"tlsSettings\": {
                \"certificates\": [{
                    \"certificateFile\": \"$CERT_PATH\",
                    \"keyFile\": \"$KEY_PATH\"
                }],
                \"alpn\": [\"http/1.1\"],
                \"serverName\": \"$DOMAIN\"
            }"
            ;;
        "vless")
            CLIENT_CONFIG="\"id\": \"$UUID\""
            TLS_SETTINGS="\"tlsSettings\": {
                \"certificates\": [{
                    \"certificateFile\": \"$CERT_PATH\",
                    \"keyFile\": \"$KEY_PATH\"
                }],
                \"alpn\": [\"http/1.1\"],
                \"serverName\": \"$DOMAIN\"
            }"
            ;;
        "shadowsocks")
            # Shadowsocks配置不需要TLS
            TLS_SETTINGS=""
            ;;
    esac

    # Shadowsocks特殊配置
    if [[ "$PROTOCOL" == "shadowsocks" ]]; then
        cat << EOF > /root/Xray/config.json
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray-access.log",
        "error": "/var/log/xray-error.log"
    },
    "inbounds": [{
        "port": $IN_PORT,
        "protocol": "shadowsocks",
        "settings": {
            "method": "$SS_METHOD",
            "password": "$PASSWORD",
            "network": "tcp,udp"
        }
    }],
    "outbounds": [{"protocol": "freedom"}]
}
EOF
    else
        cat << EOF > /root/Xray/config.json
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray-access.log",
        "error": "/var/log/xray-error.log"
    },
    "inbounds": [{
        "port": $IN_PORT,
        "protocol": "$PROTOCOL",
        "settings": {
            "clients": [{ $CLIENT_CONFIG }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "wsSettings": {
                "path": "$WS_PATH",
                "headers": { "Host": "$DOMAIN" }
            },
            $TLS_SETTINGS
        }
    }],
    "outbounds": [{"protocol": "freedom"}]
}
EOF
    fi
}

# Xray生成客户端链接
generate_links() {
    blue "\n=============== 客户端配置链接 ================"
    case "$PROTOCOL" in
        "vmess")
            VMESS_JSON=$(cat <<EOF
{
    "v": "2",
    "ps": "Xray_VMess",
    "add": "$DOMAIN",
    "port": "$IN_PORT",
    "id": "$UUID",
    "scy": "auto",
    "net": "ws",
    "type": "none",
    "host": "$DOMAIN",
    "path": "$WS_PATH",
    "tls": "tls",
    "sni": "$DOMAIN",
    "alpn": ""
}
EOF
            )
            VMESS_LINK="vmess://$(echo "$VMESS_JSON" | base64 -w 0)"
            green "VMess 链接：\n$VMESS_LINK"
            ;;
        "trojan")
            TROJAN_LINK="trojan://${TROJAN_PASSWORD}@${DOMAIN}:${IN_PORT}?security=tls&sni=${DOMAIN}&alpn=&type=ws&host=${DOMAIN}&path=${WS_PATH}#Xray_Trojan"
            green "Trojan 链接：\n$TROJAN_LINK"
            ;;
        "vless")
            VLESS_LINK="vless://${UUID}@${DOMAIN}:${IN_PORT}?security=tls&sni=${DOMAIN}&alpn=&type=ws&host=${DOMAIN}&path=${WS_PATH}#Xray_VLESS"
            green "VLESS 链接：\n$VLESS_LINK"
            ;;
        "shadowsocks")
            SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
            SS_LINK="ss://$(echo -n "${SS_METHOD}:${PASSWORD}" | base64 -w 0)@${SERVER_IP}:${IN_PORT}#Xray_Shadowsocks"
            green "Shadowsocks 链接：\n$SS_LINK"
            
            # 显示二维码
            if command -v qrencode &> /dev/null; then
                echo -e "${YELLOW}Shadowsocks 链接二维码:${NC}"
                qrencode -t ANSIUTF8 "$SS_LINK"
            else
                echo -e "${YELLOW}提示: 安装 'qrencode' 后可显示二维码。${NC}"
            fi
            ;;
    esac
    blue "================================================\n"
}

# ============================== Hysteria2 安装部分 ==============================
install_hysteria2() {
    # 生成符合RFC 4122标准的UUIDv4函数
    generate_uuid() {
        local bytes=$(od -x -N 16 /dev/urandom | head -1 | awk '{OFS=""; $1=""; print}')
        local byte7=${bytes:12:4}
        byte7=$((0x${byte7} & 0x0fff | 0x4000))
        byte7=$(printf "%04x" $byte7)
        local byte9=${bytes:20:4}
        byte9=$((0x${byte9} & 0x3fff | 0x8000))
        byte9=$(printf "%04x" $byte9)
        echo "${bytes:0:8}-${bytes:8:4}-${byte7}-${byte9}-${bytes:24:12}" | tr '[:upper:]' '[:lower:]'
    }

    # 获取服务器公网地址并格式化
    get_server_address() {
        local ipv6_ip
        local ipv4_ip
        
        # 尝试获取IPv6地址
        ipv6_ip=$(curl -s -m 5 -6 icanhazip.com 2>/dev/null || curl -s -m 5 -6 ifconfig.me 2>/dev/null)
        if [ -n "$ipv6_ip" ] && [[ "$ipv6_ip" == *":"* ]]; then
            echo "[$ipv6_ip]"
            return
        fi
        
        # 尝试获取IPv4地址
        ipv4_ip=$(curl -s -m 5 -4 icanhazip.com 2>/dev/null || curl -s -m 5 -4 ifconfig.me 2>/dev/null)
        if [ -n "$ipv4_ip" ] && [[ "$ipv4_ip" != *":"* ]]; then
            echo "$ipv4_ip"
            return
        fi
        
        # 如果都获取失败，返回本地IP
        hostname -I | awk '{print $1}'
    }

    # 安装依赖（带检测）
    install_hysteria_deps() {
        case "$OS_TYPE" in
            "alpine")
                apk update
                # 定义依赖列表
                DEPS="wget curl git openssl openrc lsof coreutils libcap"
                for pkg in $DEPS; do
                    if ! apk info -e $pkg &>/dev/null; then
                        yellow "安装 $pkg..."
                        apk add $pkg
                    else
                        green "$pkg 已安装"
                    fi
                done
                ;;
            "ubuntu"|"debian")
                apt update
                # 定义依赖列表
                DEPS="wget curl git openssl lsof coreutils libcap2-bin"
                for pkg in $DEPS; do
                    if ! dpkg -s $pkg &>/dev/null; then
                        yellow "安装 $pkg..."
                        apt install -y $pkg
                    else
                        green "$pkg 已安装"
                    fi
                done
                ;;
            "centos")
                # CentOS 7 镜像源修复
                if grep -q "CentOS Linux 7" /etc/os-release; then
                    echo "修复 CentOS 7 镜像源..."
                    sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
                    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
                    yum clean all
                fi
                
                # 安装EPEL仓库
                if ! rpm -q epel-release >/dev/null; then
                    yellow "安装EPEL仓库..."
                    yum install -y epel-release
                fi
                
                # 定义依赖列表
                DEPS="wget curl git openssl lsof coreutils libcap"
                for pkg in $DEPS; do
                    if ! rpm -q $pkg >/dev/null; then
                        yellow "安装 $pkg..."
                        yum install -y $pkg
                    else
                        green "$pkg 已安装"
                    fi
                done
                ;;
            *)
                red "不支持的系统类型！"
                exit 1
                ;;
        esac
    }

    # 主安装流程
    echo -e "${YELLOW}Hysteria 2 安装脚本${NC}"
    echo "---------------------------------------"
    
    # 安装依赖
    echo -e "${YELLOW}正在安装必要的软件包...${NC}" >&2
    install_hysteria_deps
    echo -e "${GREEN}依赖包安装成功。${NC}" >&2
    
    # 用户输入配置
    DEFAULT_MASQUERADE_URL="https://www.bing.com"
    DEFAULT_ACME_EMAIL="$(head /dev/urandom | tr -dc a-z | head -c 8)@gmail.com"
    
    echo "" >&2
    echo -e "${YELLOW}请选择 TLS 验证方式:${NC}" >&2
    echo "1. 自定义证书 (适用于已有证书或生成自签名证书)" >&2
    echo "2. ACME HTTP 验证 (需要域名指向本机IP，且本机80端口可用)" >&2
    read -p "请选择 [1-2, 默认 1]: " TLS_TYPE
    TLS_TYPE=${TLS_TYPE:-1}
    
    # 初始化变量
    CERT_PATH=""
    KEY_PATH=""
    DOMAIN=""
    SNI=""
    ACME_EMAIL=""
    
    case $TLS_TYPE in
        1) # 自定义证书模式
            echo -e "${YELLOW}--- 自定义证书模式 ---${NC}" >&2
            read -p "请输入证书 (.crt) 文件绝对路径 (回车则生成自签名证书): " USER_CERT_PATH
            if [ -z "$USER_CERT_PATH" ]; then
                if ! command -v openssl &> /dev/null; then
                    echo -e "${RED}错误: openssl 未安装，请手动安装后重试${NC}" >&2
                    exit 1
                fi
                read -p "请输入用于自签名证书的伪装域名 (默认 www.bing.com): " SELF_SIGN_SNI
                SELF_SIGN_SNI=${SELF_SIGN_SNI:-"www.bing.com"}
                SNI="$SELF_SIGN_SNI"
                mkdir -p /etc/hysteria/certs
                CERT_PATH="/etc/hysteria/certs/server.crt"
                KEY_PATH="/etc/hysteria/certs/server.key"
                echo "正在生成自签名证书..." >&2
                if ! openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
                    -keyout "$KEY_PATH" -out "$CERT_PATH" \
                    -subj "/CN=$SNI" -days 36500; then
                    echo -e "${RED}错误: 自签名证书生成失败，请检查 openssl 配置！${NC}" >&2
                    exit 1
                fi
                echo -e "${GREEN}自签名证书已生成: $CERT_PATH, $KEY_PATH${NC}" >&2
            else
                while true; do
                    read -p "请输入私钥 (.key) 文件绝对路径: " USER_KEY_PATH
                    if [ -z "$USER_CERT_PATH" ] || [ -z "$USER_KEY_PATH" ]; then
                        red "错误: 证书和私钥路径都不能为空。"
                        continue
                    fi
                    CERT_PATH=$(realpath "$USER_CERT_PATH")
                    KEY_PATH=$(realpath "$USER_KEY_PATH")
                    if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
                        red "错误: 提供的证书或私钥文件路径无效或文件不存在。"
                        continue
                    fi
                    
                    # 验证证书匹配性
                    cert_md5=$(openssl x509 -noout -modulus -in "$CERT_PATH" 2>/dev/null | openssl md5 | cut -d' ' -f2)
                    key_md5=$(openssl rsa -noout -modulus -in "$KEY_PATH" 2>/dev/null | openssl md5 | cut -d' ' -f2)
                    if [[ "$cert_md5" == "$key_md5" ]]; then
                        SNI=$(openssl x509 -noout -subject -in "$CERT_PATH" 2>/dev/null | grep -o 'CN=[^,]*' | cut -d= -f2 | tr -d ' ')
                        if [ -z "$SNI" ]; then
                            read -p "无法从证书自动提取CN(域名)，请输入您希望使用的SNI: " MANUAL_SNI
                            if [ -z "$MANUAL_SNI" ]; then
                                red "SNI 不能为空！"
                                continue
                            fi
                            SNI="$MANUAL_SNI"
                        else
                            echo "从证书中提取到的 SNI (CN): $SNI" >&2
                        fi
                        break
                    else
                        red "证书与私钥不匹配！请检查文件内容是否正确"
                        read -p "是否重新输入证书路径？[y/n] (默认y): " retry
                        [[ -z "$retry" ]] && retry="y"
                        if [[ "$retry" != "y" ]]; then
                            exit 1
                        fi
                        read -p "请重新输入证书 (.crt) 文件绝对路径: " USER_CERT_PATH
                    fi
                done
            fi
            ;;
        2) # ACME HTTP 验证模式
            echo -e "${YELLOW}--- ACME HTTP 验证模式 ---${NC}" >&2
            read -p "请输入您的域名 (例如: example.com): " DOMAIN
            if [ -z "$DOMAIN" ]; then
                echo -e "${RED}域名不能为空！${NC}" >&2
                exit 1
            fi
            read -p "请输入用于 ACME 证书申请的邮箱 (回车默认 $DEFAULT_ACME_EMAIL): " INPUT_ACME_EMAIL
            ACME_EMAIL=${INPUT_ACME_EMAIL:-$DEFAULT_ACME_EMAIL}
            if [ -z "$ACME_EMAIL" ]; then
                echo -e "${RED}邮箱不能为空！${NC}" >&2
                exit 1
            fi
            SNI=$DOMAIN
            echo "检查 80 端口占用情况..." >&2
            if lsof -i:80 -sTCP:LISTEN -P -n &>/dev/null; then
                echo -e "${YELLOW}警告: 检测到 80 端口已被占用。Hysteria 将尝试使用此端口进行 ACME 验证。${NC}" >&2
                PID_80=$(lsof -t -i:80 -sTCP:LISTEN)
                [ -n "$PID_80" ] && echo "占用80端口的进程 PID(s): $PID_80" >&2
            else
                echo "80 端口未被占用，可用于 ACME HTTP 验证。" >&2
            fi
            ;;
        *) # 无效选项
            echo -e "${RED}无效选项，退出脚本。${NC}" >&2
            exit 1
            ;;
    esac
    
    # 端口配置 - 仅手动输入或随机生成
    read -p "请输入 Hysteria 端口 (留空则生成随机端口): " PORT
    if [[ -z "$PORT" ]]; then
        # 生成 20000-50000 之间的随机端口
        PORT=$((RANDOM % 30001 + 20000))
        
        # 检查端口是否被占用
        while lsof -i :$PORT >/dev/null 2>&1 || netstat -an | grep -q ":$PORT "; do
            PORT=$((RANDOM % 30001 + 20000))
        done
        
        green "已生成随机端口: $PORT"
    fi
    
    read -p "请输入 Hysteria 密码 (回车则使用随机UUID): " PASSWORD
    if [ -z "$PASSWORD" ]; then
        PASSWORD=$(generate_uuid)
        echo "使用随机密码: $PASSWORD" >&2
    fi
    
    read -p "请输入伪装访问的目标URL (默认 $DEFAULT_MASQUERADE_URL): " MASQUERADE_URL
    MASQUERADE_URL=${MASQUERADE_URL:-$DEFAULT_MASQUERADE_URL}
    
    # 获取服务器公网地址
    SERVER_PUBLIC_ADDRESS=$(get_server_address)
    
    mkdir -p /etc/hysteria
    
    # 下载 Hysteria 二进制文件
    HYSTERIA_BIN="/usr/local/bin/hysteria"
    echo -e "${YELLOW}正在下载 Hysteria 最新版...${NC}" >&2
    ARCH=$(uname -m)
    case ${ARCH} in
        x86_64) HYSTERIA_ARCH="amd64";;
        aarch64) HYSTERIA_ARCH="arm64";;
        armv7l) HYSTERIA_ARCH="arm";;
        *) echo -e "${RED}不支持的系统架构: ${ARCH}${NC}" >&2; exit 1;;
    esac
    
    if ! wget -qO "$HYSTERIA_BIN" "https://download.hysteria.network/app/latest/hysteria-linux-${HYSTERIA_ARCH}"; then
        echo -e "${RED}下载 Hysteria 失败，请检查网络或手动下载。${NC}" >&2
        exit 1
    fi
    
    chmod +x "$HYSTERIA_BIN"
    echo -e "${GREEN}Hysteria 下载并设置权限完成: $HYSTERIA_BIN${NC}" >&2
    
    # 设置权限（ACME模式）
    if [ "$TLS_TYPE" -eq 2 ]; then
        echo "为 Hysteria 二进制文件设置权限..." >&2
        if ! command -v setcap &>/dev/null; then
            echo -e "${YELLOW}setcap 命令未找到，尝试安装依赖...${NC}" >&2
            case "$OS_TYPE" in
                "alpine") apk add libcap --no-cache >/dev/null ;;
                "ubuntu"|"debian") apt install -y libcap2-bin >/dev/null ;;
                "centos") yum install -y libcap >/dev/null ;;
            esac
        fi
        
        if ! setcap 'cap_net_bind_service=+ep' "$HYSTERIA_BIN"; then
            echo -e "${RED}错误: setcap 失败。ACME HTTP 验证可能无法工作。${NC}" >&2
        else
            echo -e "${GREEN}权限设置成功。${NC}" >&2
        fi
    fi
    
    # 生成配置文件
    echo -e "${YELLOW}正在生成配置文件 /etc/hysteria/config.yaml...${NC}" >&2
    cat > /etc/hysteria/config.yaml << EOF
listen: :$PORT
auth:
  type: password
  password: $PASSWORD
masquerade:
  type: proxy
  proxy:
    url: $MASQUERADE_URL
    rewriteHost: true
EOF

    # 根据TLS类型追加配置
    case $TLS_TYPE in
        1) # 自定义证书
            cat >> /etc/hysteria/config.yaml << EOF
tls:
  cert: $CERT_PATH
  key: $KEY_PATH
EOF
            LINK_SNI="$SNI"
            LINK_INSECURE=1
            echo -e "${YELLOW}注意: 使用自定义证书时，客户端需要设置 'insecure: true'${NC}" >&2
            ;;
        2) # ACME HTTP
            cat >> /etc/hysteria/config.yaml << EOF
acme:
  domains:
    - $DOMAIN
  email: $ACME_EMAIL
EOF
            LINK_SNI="$DOMAIN"
            LINK_INSECURE=0
            ;;
    esac
    echo -e "${GREEN}配置文件生成完毕。${NC}" >&2

    # 配置服务管理
    case "$OS_TYPE" in
        "alpine") # OpenRC 服务配置
            echo -e "${YELLOW}正在创建 OpenRC 服务文件 /etc/init.d/hysteria...${NC}" >&2
            cat > /etc/init.d/hysteria << EOF
#!/sbin/openrc-run
name="hysteria"
command="/usr/local/bin/hysteria"
command_args="server --config /etc/hysteria/config.yaml"
pidfile="/var/run/\${name}.pid"
respawn_delay=5
output_log="/var/log/hysteria.log"
error_log="/var/log/hysteria.error.log"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath -f \$output_log -m 0644
    checkpath -f \$error_log -m 0644
}

start() {
    ebegin "Starting \$name"
    # 使用正确的start-stop-daemon语法
    start-stop-daemon --start --background \\
        --exec \$command \\
        --make-pidfile --pidfile \$pidfile \\
        -- \\
        \$command_args
    eend \$?
}

stop() {
    ebegin "Stopping \$name"
    start-stop-daemon --stop --pidfile \$pidfile
    eend \$?
}
EOF
            chmod +x /etc/init.d/hysteria
            rc-update add hysteria default >/dev/null
            service hysteria stop >/dev/null 2>&1
            service hysteria start
            ;;
        "ubuntu"|"debian"|"centos")
            # systemd 服务配置
            echo -e "${YELLOW}正在创建 systemd 服务文件 /etc/systemd/system/hysteria.service...${NC}" >&2
            cat > /etc/systemd/system/hysteria.service << EOF
[Unit]
Description=Hysteria VPN Service
After=network.target

[Service]
ExecStart=$HYSTERIA_BIN server --config /etc/hysteria/config.yaml
Restart=always
User=root
LimitNOFILE=infinity
StandardOutput=file:/var/log/hysteria.log
StandardError=file:/var/log/hysteria.error.log

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable hysteria
            systemctl stop hysteria >/dev/null 2>&1
            systemctl start hysteria
            ;;
    esac

    # 等待服务启动
    echo -e "${GREEN}等待服务启动...${NC}" >&2
    sleep 3
    
    # 检查服务状态
    case "$OS_TYPE" in
        "alpine")
            if rc-service hysteria status | grep -q "started"; then
                echo -e "${GREEN}Hysteria 服务已成功启动！${NC}"
            else
                echo -e "${RED}Hysteria 服务状态异常。请检查日志:${NC}"
                echo "  输出日志: tail -n 20 /var/log/hysteria.log"
                echo "  错误日志: tail -n 20 /var/log/hysteria.error.log"
            fi
            ;;
        "ubuntu"|"debian"|"centos")
            if systemctl is-active --quiet hysteria; then
                echo -e "${GREEN}Hysteria 服务已成功启动！${NC}"
            else
                echo -e "${RED}Hysteria 服务状态异常。请检查日志:${NC}"
                systemctl status hysteria
            fi
            ;;
    esac
    
    # 生成订阅链接
    if [ "$TLS_TYPE" -eq 2 ]; then
        # ACME模式使用域名
        LINK_ADDRESS="$DOMAIN"
    else
        # 自定义证书模式使用服务器IP
        LINK_ADDRESS="$SERVER_PUBLIC_ADDRESS"
        # 如果获取IP失败，使用备用域名
        if [ -z "$LINK_ADDRESS" ]; then
            LINK_ADDRESS="$SNI"
            yellow "警告: 无法获取公网IP，将使用SNI域名作为服务器地址"
        fi
    fi
    
    SUBSCRIPTION_LINK="hysteria2://${PASSWORD}@${LINK_ADDRESS}:${PORT}/?sni=${LINK_SNI}&alpn=h3&insecure=${LINK_INSECURE}#Hysteria-${LINK_SNI}"
    
    # 显示结果
    echo ""
    echo "------------------------------------------------------------------------"
    echo -e "${GREEN}Hysteria 2 安装和配置完成！${NC}"
    echo "------------------------------------------------------------------------"
    echo "服务器地址: ${LINK_ADDRESS}"
    echo "端口: $PORT"
    echo "密码: $PASSWORD"
    echo "SNI / 伪装域名: $LINK_SNI"
    echo "伪装目标站点: $MASQUERADE_URL"
    echo "TLS 模式: $([ "$TLS_TYPE" -eq 1 ] && echo "自定义证书" || echo "ACME HTTP")"
    
    if [ "$TLS_TYPE" -eq 1 ]; then
        echo "证书路径: $CERT_PATH"
        echo "私钥路径: $KEY_PATH"
    elif [ "$TLS_TYPE" -eq 2 ]; then
        echo "ACME 邮箱: $ACME_EMAIL"
    fi
    
    echo "客户端 insecure (0=false, 1=true): $LINK_INSECURE"
    echo "------------------------------------------------------------------------"
    echo -e "${YELLOW}订阅链接 (Hysteria V2):${NC}"
    echo "$SUBSCRIPTION_LINK"
    echo "------------------------------------------------------------------------"
    
    # 显示二维码功能已移除
    
    echo "------------------------------------------------------------------------"
    echo "管理命令："
    case "$OS_TYPE" in
        "alpine")
            echo " service hysteria start - 启动服务"
            echo " service hysteria stop - 停止服务"
            echo " service hysteria restart - 重启服务"
            echo " service hysteria status - 查看状态"
            ;;
        "ubuntu"|"debian"|"centos")
            echo " systemctl start hysteria - 启动服务"
            echo " systemctl stop hysteria - 停止服务"
            echo " systemctl restart hysteria - 重启服务"
            echo " systemctl status hysteria - 查看状态"
            ;;
    esac
    echo " cat /etc/hysteria/config.yaml - 查看配置文件"
    echo " tail -f /var/log/hysteria.log - 查看实时日志"
    echo " tail -f /var/log/hysteria.error.log - 查看实时错误日志"
    
    echo "一键卸载命令："
    case "$OS_TYPE" in
        "alpine")
            echo " service hysteria stop ; rc-update del hysteria ; rm /etc/init.d/hysteria ; rm /usr/local/bin/hysteria ; rm -rf /etc/hysteria"
            ;;
        "ubuntu"|"debian"|"centos")
            echo " systemctl stop hysteria ; systemctl disable hysteria ; rm /etc/systemd/system/hysteria.service ; rm /usr/local/bin/hysteria ; rm -rf /etc/hysteria"
            ;;
    esac
    echo "------------------------------------------------------------------------"
    
    # 修复：添加暂停等待用户操作
    read -p "按回车键返回主菜单..."
}

# ============================== 卸载功能 ==============================
uninstall_xray() {
    # 检查是否安装了 Xray
    if [ ! -f "/root/Xray/xray" ]; then
        red "未找到 Xray 安装文件，可能未安装 Xray 服务！"
        sleep 2
        return
    fi
    
    echo -e "${YELLOW}开始卸载 Xray...${NC}"
    
    # 停止服务
    case "$OS_TYPE" in
        "alpine")
            service xray stop >/dev/null 2>&1
            rc-update del xray >/dev/null 2>&1
            rm -f /etc/init.d/xray
            ;;
        "debian"|"ubuntu"|"centos")
            systemctl stop xray >/dev/null 2>&1
            systemctl disable xray >/dev/null 2>&1
            rm -f /etc/systemd/system/xray.service
            systemctl daemon-reload
            ;;
    esac
    
    # 删除文件
    rm -rf /root/Xray
    rm -f /var/log/xray*.log
    
    echo -e "${GREEN}Xray 已成功卸载！${NC}"
    sleep 2
}

uninstall_hysteria2() {
    # 检查是否安装了 Hysteria2
    if [ ! -f "/usr/local/bin/hysteria" ]; then
        red "未找到 Hysteria2 安装文件，可能未安装 Hysteria2 服务！"
        sleep 2
        return
    fi
    
    echo -e "${YELLOW}开始卸载 Hysteria2...${NC}"
    
    # 停止服务
    case "$OS_TYPE" in
        "alpine")
            service hysteria stop >/dev/null 2>&1
            rc-update del hysteria >/dev/null 2>&1
            rm -f /etc/init.d/hysteria
            ;;
        "ubuntu"|"debian"|"centos")
            systemctl stop hysteria >/dev/null 2>&1
            systemctl disable hysteria >/dev/null 2>&1
            rm -f /etc/systemd/system/hysteria.service
            systemctl daemon-reload
            ;;
    esac
    
    # 删除文件
    rm -f /usr/local/bin/hysteria
    rm -rf /etc/hysteria
    rm -f /var/log/hysteria*.log
    
    echo -e "${GREEN}Hysteria2 已成功卸载！${NC}"
    sleep 2
}

# ============================== 显示客户端链接 ==============================
show_xray_links() {
    if [ ! -f "/root/Xray/config.json" ]; then
        red "未找到 Xray 配置文件，请先安装 Xray！"
        sleep 2
        return
    fi
    
    # 从配置文件中提取信息
    PROTOCOL=$(grep -A10 'inbounds' /root/Xray/config.json | grep '"protocol":' | head -1 | awk -F'"' '{print $4}')
    
    case "$PROTOCOL" in
        "vmess"|"vless"|"trojan")
            DOMAIN=$(grep -A10 'tlsSettings' /root/Xray/config.json | grep '"serverName":' | head -1 | awk -F'"' '{print $4}')
            WS_PATH=$(grep -A10 'wsSettings' /root/Xray/config.json | grep '"path":' | head -1 | awk -F'"' '{print $4}')
            IN_PORT=$(grep '"port":' /root/Xray/config.json | head -1 | awk '{print $2}' | tr -d ',')
            
            if [ -z "$DOMAIN" ]; then
                DOMAIN=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
            fi
            
            case "$PROTOCOL" in
                "vmess")
                    UUID=$(grep -A10 'clients' /root/Xray/config.json | grep '"id":' | head -1 | awk -F'"' '{print $4}')
                    VMESS_JSON=$(cat <<EOF
{
    "v": "2",
    "ps": "Xray_VMess",
    "add": "$DOMAIN",
    "port": "$IN_PORT",
    "id": "$UUID",
    "scy": "auto",
    "net": "ws",
    "type": "none",
    "host": "$DOMAIN",
    "path": "$WS_PATH",
    "tls": "tls",
    "sni": "$DOMAIN",
    "alpn": ""
}
EOF
                    )
                    VMESS_LINK="vmess://$(echo "$VMESS_JSON" | base64 -w 0)"
                    blue "\n=============== VMess 客户端链接 ================"
                    green "$VMESS_LINK"
                    ;;
                "trojan")
                    # 精确提取Trojan密码
                    PASSWORD=$(grep -A10 'clients' /root/Xray/config.json | grep '"password":' | head -1 | awk -F'"' '{print $4}')
                    TROJAN_LINK="trojan://${PASSWORD}@${DOMAIN}:${IN_PORT}?security=tls&sni=${DOMAIN}&alpn=&type=ws&host=${DOMAIN}&path=${WS_PATH}#Xray_Trojan"
                    blue "\n=============== Trojan 客户端链接 ================"
                    green "$TROJAN_LINK"
                    ;;
                "vless")
                    UUID=$(grep -A10 'clients' /root/Xray/config.json | grep '"id":' | head -1 | awk -F'"' '{print $4}')
                    VLESS_LINK="vless://${UUID}@${DOMAIN}:${IN_PORT}?security=tls&sni=${DOMAIN}&alpn=&type=ws&host=${DOMAIN}&path=${WS_PATH}#Xray_VLESS"
                    blue "\n=============== VLESS 客户端链接 ================"
                    green "$VLESS_LINK"
                    ;;
            esac
            ;;
        "shadowsocks")
            IN_PORT=$(grep '"port":' /root/Xray/config.json | head -1 | awk '{print $2}' | tr -d ',')
            METHOD=$(grep '"method":' /root/Xray/config.json | awk -F'"' '{print $4}')
            PASSWORD=$(grep '"password":' /root/Xray/config.json | awk -F'"' '{print $4}')
            SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
            
            SS_LINK="ss://$(echo -n "${METHOD}:${PASSWORD}" | base64 -w 0)@${SERVER_IP}:${IN_PORT}#Xray_Shadowsocks"
            
            blue "\n=============== Shadowsocks 客户端链接 ================"
            green "$SS_LINK"
            
            # 显示二维码
            if command -v qrencode &> /dev/null; then
                echo -e "${YELLOW}Shadowsocks 链接二维码:${NC}"
                qrencode -t ANSIUTF8 "$SS_LINK"
            else
                echo -e "${YELLOW}提示: 安装 'qrencode' 后可显示二维码。${NC}"
            fi
            ;;
        *)
            red "未知协议类型: $PROTOCOL"
            ;;
    esac
    
    echo -e "${YELLOW}==============================================${NC}"
    read -p "按回车键返回..." 
}

show_hysteria_links() {
    if [ ! -f "/etc/hysteria/config.yaml" ]; then
        red "未找到 Hysteria2 配置文件，请先安装 Hysteria2！"
        sleep 2
        return
    fi
    
    # 从配置文件中提取信息
    PORT=$(grep 'listen:' /etc/hysteria/config.yaml | awk '{print $2}' | tr -d ':')
    PASSWORD=$(grep 'password:' /etc/hysteria/config.yaml | awk '{print $2}')
    MASQUERADE_URL=$(grep 'url:' /etc/hysteria/config.yaml | awk '{print $2}')
    
    # 获取TLS类型
    if grep -q 'acme:' /etc/hysteria/config.yaml; then
        TLS_TYPE=2
        DOMAIN=$(grep 'domains:' -A1 /etc/hysteria/config.yaml | tail -1 | awk '{print $2}' | tr -d '- ')
        LINK_SNI="$DOMAIN"
        LINK_INSECURE=0
    else
        TLS_TYPE=1
        CERT_PATH=$(grep 'cert:' /etc/hysteria/config.yaml | awk '{print $2}')
        # 尝试从证书提取域名
        if [ -f "$CERT_PATH" ]; then
            LINK_SNI=$(openssl x509 -noout -subject -in "$CERT_PATH" 2>/dev/null | grep -o 'CN=[^,]*' | cut -d= -f2 | tr -d ' ')
        fi
        if [ -z "$LINK_SNI" ]; then
            LINK_SNI="your_domain.com"
        fi
        LINK_INSECURE=1
    fi
    
    # 获取服务器地址
    SERVER_PUBLIC_ADDRESS=$(curl -s -m 5 -4 ifconfig.me 2>/dev/null || curl -s -m 5 -4 ip.sb 2>/dev/null || curl -s -m 5 -4 api.ipify.org 2>/dev/null)
    if [ -z "$SERVER_PUBLIC_ADDRESS" ]; then
        SERVER_PUBLIC_ADDRESS=$(hostname -I | awk '{print $1}')
    fi
    
    if [ "$TLS_TYPE" -eq 2 ]; then
        LINK_ADDRESS="$DOMAIN"
    else
        LINK_ADDRESS="$SERVER_PUBLIC_ADDRESS"
    fi
    
    SUBSCRIPTION_LINK="hysteria2://${PASSWORD}@${LINK_ADDRESS}:${PORT}/?sni=${LINK_SNI}&alpn=h3&insecure=${LINK_INSECURE}#Hysteria-${LINK_SNI}"
    
    blue "\n=============== Hysteria2 客户端链接 ================"
    green "$SUBSCRIPTION_LINK"
    echo -e "${YELLOW}==============================================${NC}"
    
    # 二维码显示功能已移除
    
    echo -e "${YELLOW}==============================================${NC}"
    read -p "按回车键返回..." 
}

# ============================== 服务控制函数 ==============================
start_xray() {
    if [ ! -f "/root/Xray/xray" ]; then
        red "未找到 Xray 安装文件，请先安装 Xray！"
        sleep 2
        return
    fi
    
    case "$OS_TYPE" in
        "alpine")
            service xray start
            ;;
        "debian"|"ubuntu"|"centos")
            systemctl start xray
            ;;
    esac
    echo -e "${GREEN}Xray 已启动${NC}"
    sleep 2
}

stop_xray() {
    if [ ! -f "/root/Xray/xray" ]; then
        red "未找到 Xray 安装文件，请先安装 Xray！"
        sleep 2
        return
    fi
    
    case "$OS_TYPE" in
        "alpine")
            service xray stop
            ;;
        "debian"|"ubuntu"|"centos")
            systemctl stop xray
            ;;
    esac
    echo -e "${YELLOW}Xray 已停止${NC}"
    sleep 2
}

restart_xray() {
    if [ ! -f "/root/Xray/xray" ]; then
        red "未找到 Xray 安装文件，请先安装 Xray！"
        sleep 2
        return
    fi
    
    case "$OS_TYPE" in
        "alpine")
            service xray restart
            ;;
        "debian"|"ubuntu"|"centos")
            systemctl restart xray
            ;;
    esac
    echo -e "${CYAN}Xray 已重启${NC}"
    sleep 2
}

start_hysteria2() {
    if [ ! -f "/usr/local/bin/hysteria" ]; then
        red "未找到 Hysteria2 安装文件，请先安装 Hysteria2！"
        sleep 2
        return
    fi
    
    case "$OS_TYPE" in
        "alpine")
            service hysteria start
            ;;
        "ubuntu"|"debian"|"centos")
            systemctl start hysteria
            ;;
    esac
    echo -e "${GREEN}Hysteria 2 已启动${NC}"
    sleep 2
}

stop_hysteria2() {
    if [ ! -f "/usr/local/bin/hysteria" ]; then
        red "未找到 Hysteria2 安装文件，请先安装 Hysteria2！"
        sleep 2
        return
    fi
    
    case "$OS_TYPE" in
        "alpine")
            service hysteria stop
            ;;
        "ubuntu"|"debian"|"centos")
            systemctl stop hysteria
            ;;
    esac
    echo -e "${YELLOW}Hysteria 2 已停止${NC}"
    sleep 2
}

restart_hysteria2() {
    if [ ! -f "/usr/local/bin/hysteria" ]; then
        red "未找到 Hysteria2 安装文件，请先安装 Hysteria2！"
        sleep 2
        return
    fi
    
    case "$OS_TYPE" in
        "alpine")
            service hysteria restart
            ;;
        "ubuntu"|"debian"|"centos")
            systemctl restart hysteria
            ;;
    esac
    echo -e "${CYAN}Hysteria 2 已重启${NC}"
    sleep 2
}

# ============================== 修改端口功能 ==============================
change_port() {
    echo -e "${YELLOW}请选择要修改端口的服务：${NC}"
    echo "1. Xray"
    echo "2. Hysteria2"
    read -p "请选择 [1-2]: " service_choice

    case $service_choice in
        1) # Xray
            if [ ! -f "/root/Xray/config.json" ]; then
                red "未找到 Xray 配置文件，请先安装 Xray！"
                sleep 2
                return
            fi
            
            # 显示当前端口
            current_port=$(grep '"port":' /root/Xray/config.json | head -1 | awk '{print $2}' | tr -d ',')
            green "当前 Xray 端口: $current_port"
            
            # 输入新端口
            read -p "请输入新的监听端口: " new_port
            if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
                red "无效的端口号！请输入 1-65535 之间的数字。"
                sleep 2
                return
            fi
            
            # 检查端口是否被占用
            if lsof -i :$new_port >/dev/null 2>&1 || netstat -an | grep -q ":$new_port "; then
                red "端口 $new_port 已被占用，请选择其他端口！"
                sleep 2
                return
            fi
            
            # 修改配置文件
            sed -i "s/\"port\": $current_port,/\"port\": $new_port,/" /root/Xray/config.json
            
            # 重启服务
            restart_xray
            green "Xray 端口已成功修改为: $new_port"
            ;;

        2) # Hysteria2
            if [ ! -f "/etc/hysteria/config.yaml" ]; then
                red "未找到 Hysteria2 配置文件，请先安装 Hysteria2！"
                sleep 2
                return
            fi
            
            # 显示当前端口
            current_port=$(grep 'listen:' /etc/hysteria/config.yaml | awk '{print $2}' | tr -d ':')
            green "当前 Hysteria2 端口: $current_port"
            
            # 输入新端口
            read -p "请输入新的监听端口: " new_port
            if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
                red "无效的端口号！请输入 1-65535 之间的数字。"
                sleep 2
                return
            fi
            
            # 检查端口是否被占用
            if lsof -i :$new_port >/dev/null 2>&1 || netstat -an | grep -q ":$new_port "; then
                red "端口 $new_port 已被占用，请选择其他端口！"
                sleep 2
                return
            fi
            
            # 修改配置文件
            sed -i "s/listen: :$current_port/listen: :$new_port/" /etc/hysteria/config.yaml
            
            # 重启服务
            restart_hysteria2
            green "Hysteria2 端口已成功修改为: $new_port"
            ;;

        *)
            red "无效选择！"
            ;;
    esac
    sleep 2
}

# ============================== 主菜单 ==============================
show_menu() {
    clear
    echo -e "${CYAN}=============================================="
    echo " 代理协议安装管理脚本"
    echo " 支持系统: Alpine/Ubuntu/Debian/CentOS"
    echo "=============================================="
    echo -e "${NC} 安装与更新"
    echo "=============================================="
    echo -e "${YELLOW}1. 安装 Xray (VMess/Trojan/VLESS/Shadowsocks)${NC}"
    echo -e "${YELLOW}2. 安装 Hysteria 2 (UDP协议加速)${NC}"
    echo "=============================================="
    echo " 卸载服务"
    echo "=============================================="
    echo -e "${YELLOW}3. 卸载 Xray${NC}"
    echo -e "${YELLOW}4. 卸载 Hysteria 2${NC}"
    echo "=============================================="
    echo " 配置管理"
    echo "=============================================="
    echo -e "${YELLOW}5. 查看 Xray 客户端链接${NC}"
    echo -e "${YELLOW}6. 查看 Hysteria 2 客户端链接${NC}"
    echo -e "${YELLOW}7. 修改服务端口${NC}"
    echo "=============================================="
    echo " 服务控制"
    echo "=============================================="
    echo -e "${YELLOW}8. 启动 Xray${NC}"
    echo -e "${YELLOW}9. 停止 Xray${NC}"
    echo -e "${YELLOW}10. 重启 Xray${NC}"
    echo -e "${YELLOW}11. 启动 Hysteria 2${NC}"
    echo -e "${YELLOW}12. 停止 Hysteria 2${NC}"
    echo -e "${YELLOW}13. 重启 Hysteria 2${NC}"
    echo "=============================================="
    echo " 退出"
    echo "=============================================="
    echo -e "${YELLOW}0. 退出${NC}"
    echo -e "${CYAN}=============================================="
    echo -e "${NC}"

    # 检查服务状态
    echo -e "${CYAN}当前服务状态:${NC}"
    
    # Xray 状态
    if [ -f "/root/Xray/xray" ]; then
        case "$OS_TYPE" in
            "alpine")
                if rc-service xray status | grep -q "started"; then
                    echo -e " Xray: ${GREEN}已安装并运行中${NC}"
                else
                    echo -e " Xray: ${YELLOW}已安装但未运行${NC}"
                fi
                ;;
            "debian"|"ubuntu"|"centos")
                if systemctl is-active --quiet xray; then
                    echo -e " Xray: ${GREEN}已安装并运行中${NC}"
                else
                    echo -e " Xray: ${YELLOW}已安装但未运行${NC}"
                fi
                ;;
        esac
    else
        echo -e " Xray: ${RED}未安装${NC}"
    fi

    # Hysteria2 状态
    if [ -f "/usr/local/bin/hysteria" ]; then
        case "$OS_TYPE" in
            "alpine")
                if rc-service hysteria status | grep -q "started"; then
                    echo -e " Hysteria2: ${GREEN}已安装并运行中${NC}"
                else
                    echo -e " Hysteria2: ${YELLOW}已安装但未运行${NC}"
                fi
                ;;
            "ubuntu"|"debian"|"centos")
                if systemctl is-active --quiet hysteria; then
                    echo -e " Hysteria2: ${GREEN}已安装并运行中${NC}"
                else
                    echo -e " Hysteria2: ${YELLOW}已安装但未运行${NC}"
                fi
                ;;
        esac
    else
        echo -e " Hysteria2: ${RED}未安装${NC}"
    fi
    
    echo -e "${CYAN}=============================================="
    echo -e "${NC}"

    read -p "请选择操作 [0-13]: " choice
    case $choice in
        1) install_xray ; show_menu ;;
        2) install_hysteria2 ; show_menu ;;
        3) uninstall_xray ; show_menu ;;
        4) uninstall_hysteria2 ; show_menu ;;
        5) show_xray_links ; show_menu ;;
        6) show_hysteria_links ; show_menu ;;
        7) change_port ; show_menu ;;
        8) start_xray ; show_menu ;;
        9) stop_xray ; show_menu ;;
        10) restart_xray ; show_menu ;;
        11) start_hysteria2 ; show_menu ;;
        12) stop_hysteria2 ; show_menu ;;
        13) restart_hysteria2 ; show_menu ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效选择，请重新输入${NC}"; sleep 1; show_menu ;;
    esac
}

# 启动主菜单
show_menu