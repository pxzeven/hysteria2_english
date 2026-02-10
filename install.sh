#!/bin/bash
# Check if the current user is root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root!"
  echo "You can use 'sudo -i' to enter root mode."
  exit 1
fi

check_sys() {
  if [[ -f /etc/redhat-release ]]; then
    release="centos"
  elif grep -qi "debian" /etc/issue; then
    release="debian"
  elif grep -qi "ubuntu" /etc/issue; then
    release="ubuntu"
  elif grep -qi -E "centos|red hat|redhat|rocky" /etc/issue || grep -qi -E "centos|red hat|redhat|rocky" /proc/version; then
    release="centos"
  fi

  if [[ -f /etc/debian_version ]]; then
    OS_type="Debian"
    echo "Deatcted Debian system. If incorrect, please report."
  elif [[ -f /etc/redhat-release || -f /etc/centos-release || -f /etc/fedora-release || -f /etc/rocky-release ]]; then
    OS_type="CentOS"
    echo "Detected CentOS system. If incorrect, please report."
  else
    echo "Unknown"
  fi
}


_exists() {
    local cmd="$1"
    if eval type type >/dev/null 2>&1; then
      eval type "$cmd" >/dev/null 2>&1
    elif command >/dev/null 2>&1; then
      command -v "$cmd" >/dev/null 2>&1
    else
      which "$cmd" >/dev/null 2>&1
    fi
    local rt=$?
    return ${rt}
}

random_color() {
  colors=("31" "32" "33" "34" "35" "36" "37")
  echo -e "\e[${colors[$((RANDOM % 7))]}m$1\e[0m"
}

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_TYPE=$ID
    OS_VERSION=$VERSION_ID
else
    echo "Unable to determine OS type."
    exit 1
fi

install_custom_packages() {
    if [ "$OS_TYPE" = "debian" ] || [ "$OS_TYPE" = "ubuntu" ]; then
        apt update
        apt install -y wget sed sudo openssl net-tools psmisc procps iptables iproute2 ca-certificates jq
    elif [ "$OS_TYPE" = "centos" ] || [ "$OS_TYPE" = "rhel" ] || [ "$OS_TYPE" = "fedora" ] || [ "$OS_TYPE" = "rocky" ]; then
        yum install -y epel-release
        yum install -y wget sed sudo openssl net-tools psmisc procps-ng iptables iproute ca-certificates jq
    else
        echo "Unsupported OS."
        exit 1
    fi
}

install_custom_packages

echo "Installed packages:"
for pkg in wget sed openssl iptables jq; do
    if command -v $pkg >/dev/null 2>&1; then
        echo "$pkg is installed"
    else
        echo "$pkg is not installed"
    fi
done

echo "All specified packages are installed."

set_architecture() {
  case "$(uname -m)" in
    'i386' | 'i686')
     
      arch='386'
      ;;
    'amd64' | 'x86_64')
    
      arch='amd64'
      ;;
    'armv5tel' | 'armv6l' | 'armv7' | 'armv7l')
      
      arch='arm'
      ;;
    'armv8' | 'aarch64')
   
      arch='arm64'
      ;;
    'mips' | 'mipsle' | 'mips64' | 'mips64le')
      
      arch='mipsle'
      ;;
    's390x')
      
      arch='s390x'
      ;;
    *)

      echo "System temporarily unsupported, possibly because it's not within the known architecture range."
      exit 1
      ;;
  esac
}

get_installed_version() {
    if [ -x "/root/hy3/hysteria-linux-$arch" ]; then
        version="$("/root/hy3/hysteria-linux-$arch" version | grep Version | grep -o 'v[.0-9]*')"
    else
        version="Not installed yet"
    fi
}

get_latest_version() {
  local tmpfile
  tmpfile=$(mktemp)

  if ! curl -sS "https://api.hy2.io/v1/update?cver=installscript&plat=linux&arch="$arch"&chan=release&side=server" -o "$tmpfile"; then
    error "Failed to get the latest version from Hysteria 2 API, please check your network and try again."
    exit 11
  fi

  local latest_version
  latest_version=$(grep -oP '"lver":\s*\K"v.*?"' "$tmpfile" | head -1)
  latest_version=${latest_version#'"'}
  latest_version=${latest_version%'"'}

  if [[ -n "$latest_version" ]]; then
    echo "$latest_version"
  fi

  rm -f "$tmpfile"
}

checkact() {
pid=$(pgrep -f "hysteria-linux-$arch")

if [ -n "$pid" ]; then
  hy2zt="Running"
else
  hy2zt="Not running"
fi
}

BBR_grub() {
  if [[ "${OS_type}" == "CentOS" ]]; then
    if [[ ${version} == "6" ]]; then
      if [ -f "/boot/grub/grub.conf" ]; then
        sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
      elif [ -f "/boot/grub/grub.cfg" ]; then
        grub-mkconfig -o /boot/grub/grub.cfg
        grub-set-default 0
      elif [ -f "/boot/efi/EFI/centos/grub.cfg" ]; then
        grub-mkconfig -o /boot/efi/EFI/centos/grub.cfg
        grub-set-default 0
      elif [ -f "/boot/efi/EFI/redhat/grub.cfg" ]; then
        grub-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
        grub-set-default 0
      else
        echo -e "${Error} grub.conf/grub.cfg not found, please check."
        exit
      fi
    elif [[ ${version} == "7" ]]; then
      if [ -f "/boot/grub2/grub.cfg" ]; then
        grub2-mkconfig -o /boot/grub2/grub.cfg
        grub2-set-default 0
      elif [ -f "/boot/efi/EFI/centos/grub.cfg" ]; then
        grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg
        grub2-set-default 0
      elif [ -f "/boot/efi/EFI/redhat/grub.cfg" ]; then
        grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
        grub2-set-default 0
      else
        echo -e "${Error} grub.cfg not found, please check."
        exit
      fi
    elif [[ ${version} == "8" ]]; then
      if [ -f "/boot/grub2/grub.cfg" ]; then
        grub2-mkconfig -o /boot/grub2/grub.cfg
        grub2-set-default 0
      elif [ -f "/boot/efi/EFI/centos/grub.cfg" ]; then
        grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg
        grub2-set-default 0
      elif [ -f "/boot/efi/EFI/redhat/grub.cfg" ]; then
        grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
        grub2-set-default 0
      else
        echo -e "${Error} grub.cfg not found, please check."
        exit
      fi
      grubby --info=ALL | awk -F= '$1=="kernel" {print i++ " : " $2}'
    fi
  elif [[ "${OS_type}" == "Debian" ]]; then
    if _exists "update-grub"; then
      update-grub
    elif [ -f "/usr/sbin/update-grub" ]; then
      /usr/sbin/update-grub
    else
      apt install grub2-common -y
      update-grub
    fi
    #exit 1
  fi
}
check_version() {
  if [[ -s /etc/redhat-release ]]; then
    version=$(grep -oE "[0-9.]+" /etc/redhat-release | cut -d . -f 1)
  else
    version=$(grep -oE "[0-9.]+" /etc/issue | cut -d . -f 1)
  fi
  bit=$(uname -m)
  check_github
}
installxanmod1 () {
# Check if system is Debian or Ubuntu
if [[ $(cat /etc/os-release) =~ ^(Debian|Ubuntu) ]]; then
  echo "OK"
else
  echo "System is not Debian or Ubuntu"
  exit 1
fi

# Check system architecture
if [[ $(uname -m) =~ ^(x86_64|amd64) ]]; then
  echo "Installing, please wait..."
else
  echo "System architecture is not x86/amd64. Please use a compatible device."
  exit 1
fi

echo "系统符合要求，继续执行脚本"
wget -qO - https://dl.xanmod.org/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | sudo tee /etc/apt/sources.list.d/xanmod-release.list
sudo apt update && sudo apt install linux-xanmod-x64v3
BBR_grub
echo -e "${Tip} Kernel installation complete. Please check the information above to confirm success. Default boot is the highest version kernel."
echo "Installation successful. Please reboot the system manually."
}
installxanmod2 () {
  check_version
  wget -O check_x86-64_psabi.sh https://dl.xanmod.org/check_x86-64_psabi.sh
  chmod +x check_x86-64_psabi.sh
  cpu_level=$(./check_x86-64_psabi.sh | awk -F 'v' '{print $2}')
  echo -e "CPU supports \033[32m${cpu_level}\033[0m"
  # exit
  if [[ ${bit} != "x86_64" ]]; then
    echo -e "${Error} Only x86_64 system is supported!" && exit 1
  fi

  if [[ "${OS_type}" == "Debian" ]]; then
    apt update
    apt-get install gnupg gnupg2 gnupg1 sudo -y
    echo 'deb http://deb.xanmod.org releases main' | sudo tee /etc/apt/sources.list.d/xanmod-kernel.list
    wget -qO - https://dl.xanmod.org/gpg.key | sudo apt-key --keyring /etc/apt/trusted.gpg.d/xanmod-kernel.gpg add -
    if [[ "${cpu_level}" == "4" ]]; then
      apt update && apt install linux-xanmod-x64v4 -y
    elif [[ "${cpu_level}" == "3" ]]; then
      apt update && apt install linux-xanmod-x64v3 -y
    elif [[ "${cpu_level}" == "2" ]]; then
      apt update && apt install linux-xanmod-x64v2 -y
    else
      apt update && apt install linux-xanmod-x64v1 -y
    fi
  else
    echo -e "${Error} Current system ${release} ${version} ${bit} is not supported!" && exit 1
  fi

  BBR_grub
  echo -e "${Tip} Kernel installation complete. Please check the information above to confirm success. Default boot is the highest version kernel. Please reboot manually."
}
detele_kernel() {
  if [[ "${OS_type}" == "CentOS" ]]; then
    rpm_total=$(rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | wc -l)
    if [ "${rpm_total}" ] >"1"; then
      echo -e "Detected ${rpm_total} other kernels, starting uninstall..."
      for ((integer = 1; integer <= ${rpm_total}; integer++)); do
        rpm_del=$(rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | head -${integer})
        echo -e "Uninstalling ${rpm_del} kernel..."
        rpm --nodeps -e ${rpm_del}
        echo -e "Uninstallation of ${rpm_del} kernel complete, continuing..."
      done
      echo --nodeps -e "Kernel uninstallation complete, continuing..."
    else
      echo -e " Incorrect number of kernels detected, please check!" && exit 1
    fi
  elif [[ "${OS_type}" == "Debian" ]]; then
    deb_total=$(dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | wc -l)
    if [ "${deb_total}" ] >"1"; then
      echo -e "Detected ${deb_total} other kernels, starting uninstall..."
      for ((integer = 1; integer <= ${deb_total}; integer++)); do
        deb_del=$(dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer})
        echo -e "Uninstalling ${deb_del} kernel..."
        apt-get purge -y ${deb_del}
        apt-get autoremove -y
        echo -e "Uninstallation of ${deb_del} kernel complete, continuing..."
      done
      echo -e "Kernel uninstallation complete, continuing..."
    else
      echo -e " Incorrect number of kernels detected, please check!" && exit 1
    fi
  fi
}
detele_kernel_head() {
  if [[ "${OS_type}" == "CentOS" ]]; then
    rpm_total=$(rpm -qa | grep kernel-headers | grep -v "${kernel_version}" | grep -v "noarch" | wc -l)
    if [ "${rpm_total}" ] >"1"; then
      echo -e "Detected ${rpm_total} other kernel headers, starting uninstall..."
      for ((integer = 1; integer <= ${rpm_total}; integer++)); do
        rpm_del=$(rpm -qa | grep kernel-headers | grep -v "${kernel_version}" | grep -v "noarch" | head -${integer})
        echo -e "Uninstalling ${rpm_del} kernel headers..."
        rpm --nodeps -e ${rpm_del}
        echo -e "Uninstallation of ${rpm_del} kernel headers complete, continuing..."
      done
      echo --nodeps -e "Kernel headers uninstallation complete, continuing..."
    else
      echo -e " Incorrect number of kernels detected, please check!" && exit 1
    fi
  elif [[ "${OS_type}" == "Debian" ]]; then
    deb_total=$(dpkg -l | grep linux-headers | awk '{print $2}' | grep -v "${kernel_version}" | wc -l)
    if [ "${deb_total}" ] >"1"; then
      echo -e "Detected ${deb_total} other kernel headers, starting uninstall..."
      for ((integer = 1; integer <= ${deb_total}; integer++)); do
        deb_del=$(dpkg -l | grep linux-headers | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer})
        echo -e "Uninstalling ${deb_del} kernel headers..."
        apt-get purge -y ${deb_del}
        apt-get autoremove -y
        echo -e "Uninstallation of ${deb_del} kernel headers complete, continuing..."
      done
      echo -e "Kernel uninstallation complete, continuing..."
    else
      echo -e " Incorrect number of kernels detected, please check!" && exit 1
    fi
  fi
}
detele_kernel_custom() {
  BBR_grub
  read -p " Check the kernels above and enter the kernel keyword to KEEP (e.g., 5.15.0-11) :" kernel_version
  detele_kernel
  detele_kernel_head
  BBR_grub
}
welcome() {

echo -e "$(random_color '
░██  ░██
░██  ░██       ░████        ░█         ░█        ░█░█░█
░██  ░██     ░█      █      ░█         ░█        ░█    ░█
░██████     ░██████         ░█         ░█        ░█    ░█
░██  ░██     ░█             ░█ ░█      ░█  ░█     ░█░█░█
░██  ░██      ░██  █         ░█         ░█                   ')"
 echo -e "$(random_color '
Echoes of Life: One is despair, the other is complacency. ')"
 
}

echo -e "$(random_color 'Installing necessary dependencies......')"
install_missing_commands > /dev/null 2>&1
echo -e "$(random_color 'Dependencies installation complete')"

set_architecture

get_installed_version

latest_version=$(get_latest_version)

checkact

uninstall_hysteria() {

sudo systemctl stop hysteria.service

sudo systemctl disable hysteria.service

  if [ -f "/etc/systemd/system/hysteria.service" ]; then
  sudo rm "/etc/systemd/system/hysteria.service"
  echo "Hysteria server service file deleted."
else
  echo "Hysteria server service file does not exist."
fi

process_name="hysteria-linux-$arch"
pid=$(pgrep -f "$process_name")

if [ -n "$pid" ]; then
  echo "Found $process_name process (PID: $pid), killing..."
  kill "$pid"
  echo "$process_name process killed."
else
  echo "Process $process_name not found."
fi

if [ -f "/root/hy3/hysteria-linux-$arch" ]; then
  rm -f "/root/hy3/hysteria-linux-$arch"
  echo "Hysteria server binary deleted."
else
  echo "Hysteria server binary not found."
fi

if [ -f "/root/hy3/config.yaml" ]; then
  rm -f "/root/hy3/config.yaml"
  echo "Hysteria server config file deleted."
else
  echo "Hysteria server config file not found."
fi

rm -rf /root/hy3
systemctl stop ipppp.service
systemctl disable ipppp.service
rm -rf /etc/systemd/system/ipppp.service
rm -rf /bin/hy2
echo "Uninstall complete."
 }

hy2easy() {
    rm -rf /usr/local/bin/hy2
    cat <<EOF > /usr/local/bin/hy2
#!/bin/bash
wget -O hy2.py https://raw.githubusercontent.com/pxzeven/hysteria2_english/main/hysteria2.py && chmod +x hy2.py && python3 hy2.py
EOF
    chmod +x /usr/local/bin/hy2
    echo "hy2 shortcut added"
}

hy2easy
welcome

# Prompt for input
echo "$(random_color 'Select an option:')"
echo -e "$(random_color 'Enter hy2 to quick start script')"
echo "1. Install"
echo "2. Uninstall"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "3. View Config"
echo "4. Exit"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "5. Online update hy2 core (Current version: $version)"
echo "6. Manage hy2 core"
echo "7. Install Xanmod kernel (Better network performance)"
echo "Latest hy2 version: $latest_version"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "Hysteria2 Status: $hy2zt"

read -p "Enter option number (1-7): " choice

case $choice in
   1)
     #啥也没有
     ;;

   2)

uninstall_hysteria > /dev/null 2>&1
echo -e "$(random_color 'Uninstalling, please wait...')"
echo -e "$(random_color 'Uninstall complete!')"

     exit
     ;;

   4)

     # Exit script
     exit
     ;;

   3)

echo "$(random_color 'Below is your nekobox node info')"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
cd /root/hy3/

cat /root/hy3/neko.txt

echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "$(random_color 'Below is your clashmate config')"

cat /root/hy3/clash-mate.yaml

echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
     exit
     ;;
    
   5)

get_updated_version() {
    if [ -x "/root/hy3/hysteria-linux-$arch" ]; then
        version2="$("/root/hy3/hysteria-linux-$arch" version | grep Version | grep -o 'v[.0-9]*')"
    else
        version2="Not installed yet"
    fi
}

updatehy2 () {
process_name="hysteria-linux-$arch"

pid=$(pgrep -f "$process_name")

if [ -n "$pid" ]; then
  echo "Found $process_name process (PID: $pid), killing..."
  kill "$pid"
  echo "$process_name process killed."
else
  echo "Process $process_name not found."
fi

cd /root/hy3

rm -r hysteria-linux-$arch

if wget -O hysteria-linux-$arch https://download.hysteria.network/app/latest/hysteria-linux-$arch; then
  chmod +x hysteria-linux-$arch
else
  if wget -O hysteria-linux-$arch https://github.com/apernet/hysteria/releases/download/app/$latest_version/hysteria-linux-$arch; then
    chmod +x hysteria-linux-$arch
  else
    echo "Cannot download file from any website"
    exit 1
  fi
fi

systemctl stop hysteria.service
systemctl start hysteria.service

echo "Update complete."
}
echo "$(random_color 'Updating, please wait...')"
sleep 1
updatehy2 > /dev/null 2>&1
echo "$(random_color 'Update complete.')"
get_updated_version
echo "Your current updated hy2 version: $version2"

      exit
      ;;

    6)

echo "Enter 1 to start, 2 to stop, 3 to restart hy2 core"
read choicehy2
if [ "$choicehy2" = "1" ]; then
sudo systemctl start hysteria.service
echo "hy2 core started successfully"
elif [ "$choicehy2" = "2" ]; then
sudo systemctl stop hysteria.service
echo "hy2 core stopped successfully"
elif [ "$choicehy2" = "3" ]; then
sudo systemctl restart hysteria.service
echo "hy2 core restarted successfully"
else
  echo "Please enter a valid choice"
fi

      exit
      ;;


   7)

echo "Enter y to install, n to cancel, o to uninstall (y/n/o)"
read answer
if [ "$answer" = "y" ]; then
check_sys
installxanmod2
elif [ "$answer" = "n" ]; then
  echo "Canceling and exiting..."
  exit 0
elif [ "$answer" = "o" ]; then
check_sys
detele_kernel_custom
else
  echo "Invalid input. Please enter y, n, or o."
fi
     exit
     ;;

   *)
     echo "$(random_color 'Invalid choice, exiting script.')"

     exit
     ;;

esac

echo "$(random_color 'Please wait...')"
sleep 1

if [ "$hy2zt" = "Running" ]; then
  echo "Hysteria is running, please uninstall first."
  exit 1
else
  echo "Starting..."
fi

uninstall_hysteria > /dev/null 2>&1

installhy2 () {
  cd /root
  mkdir -p ~/hy3
  cd ~/hy3

  REPO_URL="https://github.com/apernet/hysteria/releases"
  LATEST_RELEASE=$(curl -s $REPO_URL/latest | jq -r '.tag_name')
  DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/$LATEST_RELEASE/hysteria-linux-$arch"

  if wget -O hysteria-linux-$arch https://download.hysteria.network/app/latest/hysteria-linux-$arch; then
    chmod +x hysteria-linux-$arch
  else
    if wget -O hysteria-linux-$arch $DOWNLOAD_URL; then
      chmod +x hysteria-linux-$arch
    else
      echo "无法从任何网站下载文件"
      exit 1
    fi
  fi

  echo "Latest release version: $LATEST_RELEASE"
  echo "Download URL: $DOWNLOAD_URL"
}

echo "$(random_color 'Downloading...')"
sleep 1
installhy2 > /dev/null 2>&1

# 就是写一个配置文件，你可以自己修改，别乱搞就行，安装hysteria2文档修改
cat <<EOL > config.yaml
listen: :443



auth:
  type: password
  password: Se7RAuFZ8Lzg

masquerade:
  type: proxy
  file:
    dir: /www/masq
  proxy:
    url: https://news.ycombinator.com/
    rewriteHost: true
  string:
    content: hello stupid world
    headers:
      content-type: text/plain
      custom-stuff: ice cream so good
    statusCode: 200

bandwidth:
  up: 0 gbps
  down: 0 gbps

udpIdleTimeout: 90s

EOL

while true; do
    echo "$(random_color 'Enter port (Leave blank for 443, 0 for random 2000-60000, or specific 1-65535): ')"
    read -p "" port
  
    if [ -z "$port" ]; then
      port=443
    elif [ "$port" -eq 0 ]; then
      port=$((RANDOM % 58001 + 2000))
    elif ! [[ "$port" =~ ^[0-9]+$ ]]; then
      echo "$(random_color 'Please enter a valid number, try again: ')"
      continue
    fi
  
    while netstat -tuln | grep -q ":$port "; do
      echo "$(random_color 'Port occupied, please enter another port: ')"
      read -p "" port
    done
  
    if sed -i "s/443/$port/" config.yaml; then
      echo "$(random_color 'Port set to: ')" "$port"
    else
      echo "$(random_color 'Failed to set port, exiting.')"
      exit 1
    fi
  

generate_certificate() {
    read -p "Enter domain for self-signed cert (Default bing.com): " user_domain
    domain_name=${user_domain:-"bing.com"}
    if curl --output /dev/null --silent --head --fail "$domain_name"; then
        mkdir -p /etc/ssl/private
        openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout "/etc/ssl/private/$domain_name.key" -out "/etc/ssl/private/$domain_name.crt" -subj "/CN=$domain_name" -days 36500
        chmod 777 "/etc/ssl/private/$domain_name.key" "/etc/ssl/private/$domain_name.crt"
        echo -e "Self-signed certificate and private key generated!"
    else
        echo -e "Invalid domain or domain unreachable, please enter a valid domain!"
        generate_certificate
    fi
}

read -p "Select certificate type (1 for ACME, 2 for Self-signed, Enter for ACME default): " cert_choice

if [ "$cert_choice" == "2" ]; then
    generate_certificate

    certificate_path="/etc/ssl/private/$domain_name.crt"
    private_key_path="/etc/ssl/private/$domain_name.key"

    echo -e "Certificate file saved to /etc/ssl/private/$domain_name.crt"
    echo -e "Private key file saved to /etc/ssl/private/$domain_name.key"

    temp_file=$(mktemp)
    echo -e "temp_file: $temp_file"
    sed '3i\tls:\n  cert: '"/etc/ssl/private/$domain_name.crt"'\n  key: '"/etc/ssl/private/$domain_name.key"'' /root/hy3/config.yaml > "$temp_file"
    mv "$temp_file" /root/hy3/config.yaml
    touch /root/hy3/ca
   # Added a small variable here
    ovokk="insecure=1&"
    choice1="true"
    echo -e "Certificate and key info written to /root/hy3/config.yaml."
    
get_ipv4_info() {
  ip_address=$(wget -4 -qO- --no-check-certificate --user-agent=Mozilla --tries=2 --timeout=3 http://ip-api.com/json/) &&
  
  ispck=$(expr "$ip_address" : '.*isp\":[ ]*\"\([^"]*\).*')

  if echo "$ispck" | grep -qi "cloudflare"; then
    echo "Warp detected, please enter correct server IP:"
    read new_ip
    ipwan="$new_ip"
  else
    ipwan="$(expr "$ip_address" : '.*query\":[ ]*\"\([^"]*\).*')"
  fi
}

get_ipv6_info() {
  ip_address=$(wget -6 -qO- --no-check-certificate --user-agent=Mozilla --tries=2 --timeout=3 https://api.ip.sb/geoip) &&
  
  ispck=$(expr "$ip_address" : '.*isp\":[ ]*\"\([^"]*\).*')

  if echo "$ispck" | grep -qi "cloudflare"; then
    echo "Warp detected, please enter correct server IP:"
    read new_ip
    ipwan="[$new_ip]"
  else
    ipwan="[$(expr "$ip_address" : '.*ip\":[ ]*\"\([^"]*\).*')]"
  fi
}

while true; do
  echo "1. IPv4 Mode"
  echo "2. IPv6 Mode"
  echo "Press Enter to select default IPv4 Mode."

  read -p "Please select: " choice

  case $choice in
    1)
      get_ipv4_info
      echo "Your IP Address is: $ipwan"
      ipta="iptables"
      break
      ;;
    2)
      get_ipv6_info
      echo "Your IP Address is: $ipwan"
      ipta="ip6tables"
      break
      ;;
    "")
      echo "Using default IPv4 Mode."
      get_ipv4_info
      echo "Your IP Address is: $ipwan"
      ipta="iptables"
      break
      ;;
    *)
      echo "Invalid input. Please enter 1 or 2, or press Enter for default IPv4 Mode."
      ;;
  esac
done

fi

if [ -f "/root/hy3/ca" ]; then
  echo "$(random_color '/root/hy3/ folder already contains a file named ca. Skipping addition.')"
else

  echo "$(random_color 'Enter your domain (Must be resolved): ')"
  read -p "" domain

  while [ -z "$domain" ]; do
    echo "$(random_color 'Domain cannot be empty, please re-enter: ')"
    read -p "" domain
  done


  echo "$(random_color 'Enter your email (Default random): ')"
  read -p "" email

  if [ -z "$email" ]; then

    random_part=$(head /dev/urandom | LC_ALL=C tr -dc A-Za-z0-9 | head -c 6 ; echo '')

    email="${random_part}@gmail.com"
  fi

  if [ -f "config.yaml" ]; then
    echo -e "\nAppending to config.yaml..."
    sed -i '3i\acme:\n  domains:\n    - '$domain'\n  email: '$email'' config.yaml
    echo "$(random_color 'Domain and email added to config.yaml.')"
    ipta="iptables"
    choice2="false"
  else
    echo "$(random_color 'config.yaml not found, cannot add.')"
    exit 1
  fi
fi

echo "Please select an option:"
echo "1. Enable DNS certificate application (Default Cloudflare, requires API token, email must be registered)"
echo "2. Skip (Self-signed users or unsure, default skip)"

read -p "Enter your choice (1 or 2): " choice

# 如果用户直接按回车，默认选择2
if [ -z "$choice" ]; then
    choice=2
fi

if [ "$choice" -eq 1 ]; then
    read -p "Enter Cloudflare API Token: " api_key

    # Find the line number of 'email'
    line_number=$(grep -n "email" /root/hy3/config.yaml | cut -d: -f1)

    if [ -z "$line_number" ]; then
        echo "Email line not found, please check config file."
        exit 1
    fi

    sed -i "${line_number}a\\
  type: dns\\
  dns:\\
    name: cloudflare\\
    config:\\
      cloudflare_api_token: $api_key" /root/hy3/config.yaml

    echo "Configuration successfully added to /root/hy3/config.yaml"
else
    echo "Skipping DNS configuration."
fi

echo "$(random_color 'Enter your password (Leave blank for random, max 20 chars): ')"
read -p "" password

if [ -z "$password" ]; then
  password=$(openssl rand -base64 20 | tr -dc 'a-zA-Z0-9')
fi

if sed -i "s/Se7RAuFZ8Lzg/$password/" config.yaml; then
  echo "$(random_color 'Password set to: ')" $password
else
  echo "$(random_color 'Failed to set password, exiting.')"
  exit 1
fi

echo "$(random_color 'Enter masquerade URL (Default https://news.ycombinator.com/): ')"
read -p "" masquerade_url

if [ -z "$masquerade_url" ]; then
  masquerade_url="https://news.ycombinator.com/"
fi

if sed -i "s|https://news.ycombinator.com/|$masquerade_url|" config.yaml; then
  echo "$(random_color 'Masquerade URL set to: ')" $masquerade_url
else
  echo "$(random_color 'Failed to set masquerade URL, exiting.')"
  exit 1
fi
   
    echo "$(random_color 'Enable port hopping? (Enter to skip, 1 to enable): ')"
    read -p "" port_jump
  
    if [ -z "$port_jump" ]; then
      
      break
    elif [ "$port_jump" -eq 1 ]; then
    
      echo "$(random_color 'Enter start port (Start must be < End): ')"
      read -p "" start_port
  
      echo "$(random_color 'Enter end port (End must be > Start): ')"
      read -p "" end_port
  
     if [ "$start_port" -lt "$end_port" ]; then

"$ipta" -t nat -A PREROUTING -i eth0 -p udp --dport "$start_port":"$end_port" -j DNAT --to-destination :"$port"
        echo "$(random_color 'Port hopping enabled, redirecting range to main port: ')" "$port"
        break
      else
        echo "$(random_color 'End port must be > Start port, please re-enter.')"
      fi
    else
      echo "$(random_color 'Invalid input. Enter 1 to enable or Enter to skip.')"
    fi
done

if [ -n "$port_jump" ] && [ "$port_jump" -eq 1 ]; then
  echo "#!/bin/bash" > /root/hy3/ipppp.sh
  echo "$ipta -t nat -A PREROUTING -i eth0 -p udp --dport $start_port:$end_port -j DNAT --to-destination :$port" >> /root/hy3/ipppp.sh
  
 
  chmod +x /root/hy3/ipppp.sh
  
  echo "[Unit]" > /etc/systemd/system/ipppp.service
  echo "Description=IP Port Redirect" >> /etc/systemd/system/ipppp.service
  echo "" >> /etc/systemd/system/ipppp.service
  echo "[Service]" >> /etc/systemd/system/ipppp.service
  echo "ExecStart=/root/hy3/ipppp.sh" >> /etc/systemd/system/ipppp.service
  echo "" >> /etc/systemd/system/ipppp.service
  echo "[Install]" >> /etc/systemd/system/ipppp.service
  echo "WantedBy=multi-user.target" >> /etc/systemd/system/ipppp.service
  
  # 启用开机自启动服务
  systemctl enable ipppp.service
  
  # 启动服务
  systemctl start ipppp.service
  
  echo "$(random_color '/ipppp.sh created and set to auto-start.')"
fi

fuser -k -n udp $port

cat <<EOL > clash-mate.yaml
system-port: 7890
external-controller: 127.0.0.1:9090
allow-lan: false
mode: rule
log-level: info
ipv6: true
unified-delay: true
profile:
  store-selected: true
  store-fake-ip: true
tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true
dns:
  enable: true
  prefer-h3: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  nameserver:
    - 223.5.5.5
    - 8.8.8.8
proxies:
  - name: Hysteria2
    type: hysteria2
    server: $domain$ipwan
    port: $port
    password: $password
    sni: $domain$domain_name
    skip-cert-verify: $choice1$choice2
proxy-groups:
  - name: auto
    type: select
    proxies:
      - Hysteria2
rules:
  - MATCH,auto
EOL
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "
clash-mate.yaml saved to current folder
"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"

if nohup ./hysteria-linux-$arch server & then
  echo "$(random_color '
  Hysteria Server started.')"
else
  echo "$(random_color 'Failed to start Hysteria Server, exiting.')"
  exit 1
fi
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
hysteria_directory="/root/hy3/"
hysteria_executable="/root/hy3/hysteria-linux-$arch"
hysteria_service_file="/etc/systemd/system/hysteria.service"

create_and_configure_service() {
  if [ -e "$hysteria_directory" ] && [ -e "$hysteria_executable" ]; then
    cat > "$hysteria_service_file" <<EOF
[Unit]
Description=My Hysteria Server

[Service]
Type=simple
WorkingDirectory=$hysteria_directory
ExecStart=$hysteria_executable server
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    echo "Hysteria server service file created and configured."
  else
    echo "Hysteria directory or executable not found, check path."
    exit 1
  fi
}

enable_and_start_service() {
  if [ -f "$hysteria_service_file" ]; then
    systemctl enable hysteria.service
    systemctl start hysteria.service
    echo "Hysteria server service enabled and started."
  else
    echo "Hysteria service file not found, please create config first."
    exit 1
  fi
}

create_and_configure_service
enable_and_start_service

echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "
Done.
"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"

echo "$(random_color 'Almost done...') "
sleep 2

echo "$(random_color '
Here is your clash config:')"
cat /root/hy3/clash-mate.yaml

echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"
echo "$(random_color '>>>>>>>>>>>>>>>>>>>>')"

if [ -n "$start_port" ] && [ -n "$end_port" ]; then

  echo -e "$(random_color 'Here is your Hysteria2 node link info, please save it (Please use latest neko): ')\nhysteria2://$password@$ipwan$domain:$port/?${ovokk}mport=$port,$start_port-$end_port&sni=$domain$domain_name#Hysteria2"
  
  echo "hysteria2://$password@$ipwan$domain:$port/?${ovokk}mport=$port,$start_port-$end_port&sni=$domain$domain_name#Hysteria2" > neko.txt
  
else

  echo -e "$(random_color 'Here is your Hysteria2 node link info, please save it: ')\nhysteria2://$password@$ipwan$domain:$port/?${ovokk}sni=$domain$domain_name#Hysteria2"
  
  echo "hysteria2://$password@$ipwan$domain:$port/?${ovokk}sni=$domain$domain_name#Hysteria2" > neko.txt
  
fi

echo -e "$(random_color '

Hysteria2 installation successful, please use responsibly.')"
