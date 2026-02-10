#!/bin/bash

install_dependencies() {
    local package_manager=$1
    local debian_packages=(
        curl sudo openssl qrencode net-tools procps iptables ca-certificates 
        python3 python3-pip python3-requests  # Install core Python packages directly from the system repository
    )
    local redhat_packages=(
        curl sudo openssl qrencode net-tools procps iptables ca-certificates 
        python3 python3-pip
    )

    echo "Installing dependencies using $package_manager..."
    if [ "$package_manager" == "apt" ]; then
        apt update && apt install -y "${debian_packages[@]}"
        # Disable Debian's pip protection mechanism (admin confirmation required)
        rm -f /etc/python3.*/EXTERNALLY-MANAGED 2>/dev/null
    elif [ "$package_manager" == "dnf" ]; then
        dnf install -y epel-release
        dnf install -y "${redhat_packages[@]}"
    fi

    # Globally install extra Python dependencies (break-system-packages forced)
    python3 -m pip install --break-system-packages -q requests 2>/dev/null
}

check_linux_system() {
    local os_info=$(grep -i '^id=' /etc/os-release | cut -d= -f2- | tr -d '"')

    case $os_info in
        ubuntu|debian)
            install_dependencies "apt"
            ;;
        rocky|centos|fedora)
            install_dependencies "dnf"
            ;;
        *)
            echo -e "\033[31mUnsupported Linux distribution\033[0m"
            exit 1
            ;;
    esac
}

# Call main function
check_linux_system
