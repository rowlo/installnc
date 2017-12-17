#!/bin/bash
# Bash install script for nextcloud server in VirtualBox guest with SSL and nginx as subdir in dyndns domain and nextcloud_data dir linked to a shared folder.
# The script follows the description on that awesome guide:
# https://decatec.de/home-server/nextcloud-auf-ubuntu-server-mit-nginx-mariadb-php-lets-encrypt-redis-und-fail2ban/
# But it also utilizes
# https://unix.stackexchange.com/a/345518
# https://unix.stackexchange.com/questions/335609/how-to-mount-shared-folder-from-virtualbox-at-boot-time-in-debian
# https://www.freedesktop.org/software/systemd/man/systemd.mount.html
# Original author of that script: Robert Wloch (robert@rowlo.de)

SERVER_DOMAIN_NAME="your-dyndns-domain.com"

VIRTUALBOX_SHARED_FOLDER_NAME_NEXTCLOUD_DATA="cloud-data"
MOUNTPOINTVBOXFS="/media/sfclouddata"

NGINX_GATEWAY_CONFFILE="/etc/nginx/conf.d/${SERVER_DOMAIN_NAME}.conf"
NGINX_LETSENCRYPT_CONFFILE="/etc/nginx/conf.d/${SERVER_DOMAIN_NAME}_letsencrypt.conf"
NGINX_NEXTCLOUD_CONFFILE="/etc/nginx/conf.d/${SERVER_DOMAIN_NAME}_nextcloud.conf"

CURRENT_DIR=`pwd`
SCRIPT_DIR=`dirname "${0}"`
SCRIPT=`basename "$0"`

DISTRIBUTION_CODENAME=`cat /etc/lsb-release | grep DISTRIB_CODENAME | cut -d = -f 2`
LOCAL_GATEWAY=`ip route get 1.1.1.1 | awk '{print $3; exit}'`
LOCAL_IFACE=`ip route get 1.1.1.1 | awk '{print $5; exit}'`
LOCAL_IP=`ip route get 1.1.1.1 | awk '{print $7; exit}'`

cd "${SCRIPT_DIR}"

function update_vim_dkms_ssh {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    echo "Update the system and install basic tools..."
    apt-get -yq update && apt-get -yq upgrade -V && apt-get -yq dist-upgrade && apt-get -yq autoremove
    echo "Install vim, dkms (needed for Virtual Box), openssh-server..."
    apt-get -yq install vim dkms openssh-server openssl-blacklist openssl-blacklist-extra
    
    echo "Now copy pub ssh key to that server and test that ssh login works without password. To copy the key use:"
    echo "ssh-copy-id ${SUDO_USER}@${HOSTNAME}"
    read -p "Press any key to continue and restart ssh server (after restart it will not accept password logins any more)..."
    SSH_CONFIG="/etc/ssh/sshd_config"
    if [ ! -f "${SSH_CONFIG}.original" ]; then
        cp "${SSH_CONFIG}" "${SSH_CONFIG}.original"
    else
        cp "${SSH_CONFIG}.original" "${SSH_CONFIG}"
    fi
    # comment in and enable
    sed -i -e 's/#PubkeyAuthentication no/PubkeyAuthentication yes/g' "${SSH_CONFIG}"
    # enable
    sed -i -e 's/PubkeyAuthentication no/PubkeyAuthentication yes/g' "${SSH_CONFIG}"
    # comment in and disable
    sed -i -e 's/#PasswordAuthentication yes/PasswordAuthentication no/g' "${SSH_CONFIG}"
    # disable
    sed -i -e 's/PasswordAuthentication yes/PasswordAuthentication no/g' "${SSH_CONFIG}"
    # comment in and disable
    sed -i -e 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/g' "${SSH_CONFIG}"
    # disable
    sed -i -e 's/ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/g' "${SSH_CONFIG}"
    echo "Changes to ${SSH_CONFIG}"
    diff "${SSH_CONFIG}.original" "${SSH_CONFIG}" | grep -e '^>'
    service ssh restart
    
    echo "SSH server was restarted. Please test ssh login again."
    
    read -p "Press any key to reboot the server now. CTRL+C to abort."
    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}
    reboot
}

function vbox_additions {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    echo "Make sure your VM is assigned a shared folder \"${VIRTUALBOX_SHARED_FOLDER_NAME_NEXTCLOUD_DATA}\" and that the folder contains a folder \"nextcloud_data\". The shared folder MUST NOT auto mount at system startup!"
    read -p "Press any key to continue or CTRL+C to abort if the shared folder is not prepared yet."
    ln -s "${MOUNTPOINTVBOXFS}/nextcloud_data" /var/nextcloud_data
    mkdir -p "${MOUNTPOINTVBOXFS}"
    chown www-data:www-data "${MOUNTPOINTVBOXFS}"

    WWWDATA_UID=`cat /etc/passwd | grep www-data | cut -d ':' -f 3`
    WWWDATA_GID=`cat /etc/group | grep www-data | cut -d ':' -f 3`
    # https://unix.stackexchange.com/a/345518
    SYSTEMD_MOUNT_UNIT_NAME=`systemd-escape -p --suffix=mount "${MOUNTPOINTVBOXFS}"`
    # https://unix.stackexchange.com/questions/335609/how-to-mount-shared-folder-from-virtualbox-at-boot-time-in-debian
    # https://www.freedesktop.org/software/systemd/man/systemd.mount.html
    SYSTEMD_MOUNT="/etc/systemd/system/${SYSTEMD_MOUNT_UNIT_NAME}"
    touch "${SYSTEMD_MOUNT}"
    echo "[Unit]
Requires=vboxadd-service.service
After=vboxadd-service.service

[Mount]
What=${VIRTUALBOX_SHARED_FOLDER_NAME_NEXTCLOUD_DATA}
Where=${MOUNTPOINTVBOXFS}
Type=vboxsf
Options=umask=0007,uid=${WWWDATA_UID},gui=${WWWDATA_GID}

[Install]
WantedBy = multi-user.target
" > "${SYSTEMD_MOUNT}"
    systemctl enable ${SYSTEMD_MOUNT_UNIT_NAME}

    read -p "Please insert the VirtualBox GuestAddtions and mount the drive now. When ready, press any key to continue..."
    VBOXADDITIONS=`ls /media/${SUDO_USER}/ | grep VBOXADDITIONS`
    cd /media/${SUDO_USER}/${VBOXADDITIONS}
    ./VBoxLinuxAdditions.run

    read -p "Press any key to reboot the server now. CTRL+C to abort."
    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}
    reboot
}

function install_nginx {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    # nginx is in default sources already, don't add extra repository, just install it
    apt-get -yq install nginx nginx-doc nginx-extras
    
    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}
}

function install_mariadb {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    # mariadb is in default sources already, don't add extra repository, just install it
    apt-get -yq install mariadb-server
    
    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}
}

function install_php {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    apt-get -yq install php7.0-fpm php7.0-gd php7.0-mysql php7.0-curl php7.0-xml php7.0-zip php7.0-intl php7.0-mcrypt php7.0-mbstring php7.0-bz2 php-apcu

    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}
}

function configure_php {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    # make sure www-data is user and group in php's www.conf
    WWW_CONF="/etc/php/7.0/fpm/pool.d/www.conf"
    if [ ! -f "${WWW_CONF}.original" ]; then
        cp "${WWW_CONF}" "${WWW_CONF}.original"
    else
        cp "${WWW_CONF}.original" "${WWW_CONF}"
    fi
    sed -i -e '/^user =/c\user = www-data' "${WWW_CONF}"
    sed -i -e '/^group =/c\group = www-data' "${WWW_CONF}"
    # enable socket configuration
    sed -i -e '/^listen =/c\listen = \/run\/php\/php7.0-fpm.sock' "${WWW_CONF}"
    # enable env entries (required by nextcloud
    sed -i -e 's/;env\[/env\[/g' "${WWW_CONF}"
    echo "Changes to ${WWW_CONF}"
    diff "${WWW_CONF}.original" "${WWW_CONF}" | grep -e '^>'

    # change global php settings
    PHP_INI="/etc/php/7.0/fpm/php.ini"
    if [ ! -f "${PHP_INI}.original" ]; then
        cp "${PHP_INI}" "${PHP_INI}.original"
    else
        cp "${PHP_INI}.original" "${PHP_INI}"
    fi
    sed -i -e '/^;cgi.fix_pathinfo=/c\cgi.fix_pathinfo = 0' "${PHP_INI}"
    sed -i -e '/^cgi.fix_pathinfo=/c\cgi.fix_pathinfo = 0' "${PHP_INI}"
    sed -i -e '/^;open_basedir =/c\open_basedir = \/var\/www\/:\/tmp\/' "${PHP_INI}"
    sed -i -e '/^open_basedir =/c\open_basedir = \/var\/www\/:\/tmp\/' "${PHP_INI}"
    sed -i -e '/^;opcache.enable=/c\opcache.enable = 1' "${PHP_INI}"
    sed -i -e '/^opcache.enable=/c\opcache.enable = 1' "${PHP_INI}"
    sed -i -e '/^;opcache.enable_cli=/c\opcache.enable_cli = 1' "${PHP_INI}"
    sed -i -e '/^opcache.enable_cli=/c\opcache.enable_cli = 1' "${PHP_INI}"
    sed -i -e '/^;opcache.memory_consumption=/c\opcache.memory_consumption = 128' "${PHP_INI}"
    sed -i -e '/^opcache.memory_consumption=/c\opcache.memory_consumption = 128' "${PHP_INI}"
    sed -i -e '/^;opcache.interned_strings_buffer=/c\opcache.interned_strings_buffer = 8' "${PHP_INI}"
    sed -i -e '/^opcache.interned_strings_buffer=/c\opcache.interned_strings_buffer = 8' "${PHP_INI}"
    sed -i -e '/^;opcache.max_accelerated_files=/c\opcache.max_accelerated_files = 10000' "${PHP_INI}"
    sed -i -e '/^opcache.max_accelerated_files=/c\opcache.max_accelerated_files = 10000' "${PHP_INI}"
    sed -i -e '/^;opcache.revalidate_freq=/c\opcache.revalidate_freq = 1' "${PHP_INI}"
    sed -i -e '/^opcache.revalidate_freq=/c\opcache.revalidate_freq = 1' "${PHP_INI}"
    sed -i -e '/^;opcache.save_comments=/c\opcache.save_comments = 1' "${PHP_INI}"
    sed -i -e '/^opcache.save_comments=/c\opcache.save_comments = 1' "${PHP_INI}"
    echo "Changes to ${PHP_INI}"
    diff "${PHP_INI}.original" "${PHP_INI}" | grep -e '^>'

    # prepare chron job
    CLI_PHP_INI="/etc/php/7.0/cli/php.ini"
    if [ ! -f "${CLI_PHP_INI}.original" ]; then
        cp "${CLI_PHP_INI}" "${CLI_PHP_INI}.original"
    else
        cp "${CLI_PHP_INI}.original" "${CLI_PHP_INI}"
    fi
    sed -i -e '/^;cgi.fix_pathinfo=/c\cgi.fix_pathinfo = 0' "${CLI_PHP_INI}"
    sed -i -e '/^cgi.fix_pathinfo=/c\cgi.fix_pathinfo = 0' "${CLI_PHP_INI}"
    sed -i -e '/^;open_basedir =/c\open_basedir = \/var\/www\/:\/tmp\/:\/var\/nextcloud_data\/' "${CLI_PHP_INI}"
    sed -i -e '/^open_basedir =/c\open_basedir = \/var\/www\/:\/tmp\/:\/var\/nextcloud_data\/' "${CLI_PHP_INI}"
    echo "Changes to ${CLI_PHP_INI}"
    diff "${CLI_PHP_INI}.original" "${CLI_PHP_INI}" | grep -e '^>'

    service php7.0-fpm restart
    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}
}

function configure_mariadb {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    echo "Improving security of MariaDB. You should answer the following questions with 'y' (YES). Please, set a database root password if you didn't already!"
    read -p "Press any key to proceed..."
    mysql_secure_installation
    
    service mysql restart
    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}
}

function configure_nginx {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    # modify global configuration
    NGINX_CONF="etc/nginx/nginx.conf"
    if [ ! -f "${NGINX_CONF}.original" ]; then
        cp "${NGINX_CONF}" "${NGINX_CONF}.original"
    else
        cp "${NGINX_CONF}.original" "${NGINX_CONF}"
    fi
    sed -i -e '/^user /c\user www-data;' "${NGINX_CONF}"
    sed -i -e '/^worker_processes /c\worker_processes auto;' "${NGINX_CONF}"
    sed -i -e '/# server_tokens /c\server_tokens off;' "${NGINX_CONF}"
    sed -i -e '/server_tokens /c\server_tokens off;' "${NGINX_CONF}"
    echo "Changes to ${NGINX_CONF}"
    diff "${NGINX_CONF}.original" "${NGINX_CONF}" | grep -e '^>'

    # deactivate default page
    if [ -f "/etc/nginx/sites-enabled/default" ]; then
        rm "/etc/nginx/sites-enabled/default"
    fi
    if [ -f "/etc/nginx/conf.d/default.conf" ]; then
        mv "/etc/nginx/conf.d/default.conf" "/etc/nginx/conf.d/default.conf_disabled"
    fi

    # prepare folders
    mkdir -p /var/www/letsencrypt
    mkdir -p /var/www/nextcloud
    # /var/nextcloud_data was already created as symlinc in step vbox_additions
    #mkdir -p /var/nextcloud_data
    if [ -d "${MOUNTPOINTVBOXFS}/nextcloud_data" ]; then
        ISODATE=`date --iso-8601`
        mv "${MOUNTPOINTVBOXFS}/nextcloud_data" "${MOUNTPOINTVBOXFS}/nextcloud_data_${ISODATE}"
    fi
    mkdir "${MOUNTPOINTVBOXFS}/nextcloud_data"
    chown -R www-data:www-data "${MOUNTPOINTVBOXFS}/nextcloud_data"
    chown -R www-data:www-data /var/www
    chown -R www-data:www-data /var/nextcloud_data
    if [ -d "/var/www/html" ]; then
        rm -r "/var/www/html"
    fi
    echo "<!-- -->" > /var/www/index.html

    if [ ! -f "${NGINX_GATEWAY_CONFFILE}" ]; then
        touch "${NGINX_GATEWAY_CONFFILE}"
        echo "server {" >> "${NGINX_GATEWAY_CONFFILE}"
        echo "  listen 80 default_server;" >> "${NGINX_GATEWAY_CONFFILE}"
        echo "  server_name ${SERVER_DOMAIN_NAME} ${LOCAL_IP} ${HOSTNAME};" >> "${NGINX_GATEWAY_CONFFILE}"
        echo "" >> "${NGINX_GATEWAY_CONFFILE}"
        echo "  root /var/www;" >> "${NGINX_GATEWAY_CONFFILE}"
        echo "" >> "${NGINX_GATEWAY_CONFFILE}"
        echo "  location ^~ /.well-known/acme-challenge {" >> "${NGINX_GATEWAY_CONFFILE}"
        echo "      proxy_pass http://127.0.0.1:81;" >> "${NGINX_GATEWAY_CONFFILE}"
        echo "      proxy_redirect off;" >> "${NGINX_GATEWAY_CONFFILE}"
        echo "  }" >> "${NGINX_GATEWAY_CONFFILE}"
        echo "}" >> "${NGINX_GATEWAY_CONFFILE}"
        
        echo "Changes to ${NGINX_GATEWAY_CONFFILE}"
        cat "${NGINX_GATEWAY_CONFFILE}"
    fi

    if [ ! -f "${NGINX_LETSENCRYPT_CONFFILE}" ]; then
        touch "${NGINX_LETSENCRYPT_CONFFILE}"
        echo "server {" >> "${NGINX_LETSENCRYPT_CONFFILE}"
        echo "  listen 127.0.0.1:81;" >> "${NGINX_LETSENCRYPT_CONFFILE}"
        echo "  server_name 127.0.0.1;" >> "${NGINX_LETSENCRYPT_CONFFILE}"
        echo "" >> "${NGINX_LETSENCRYPT_CONFFILE}"
        echo "  location ^~ /.well-known/acme-challenge {" >> "${NGINX_LETSENCRYPT_CONFFILE}"
        echo "      default_type text/plain;" >> "${NGINX_LETSENCRYPT_CONFFILE}"
        echo "      root /var/www/letsencrypt;" >> "${NGINX_LETSENCRYPT_CONFFILE}"
        echo "  }" >> "${NGINX_LETSENCRYPT_CONFFILE}"
        echo "}" >> "${NGINX_LETSENCRYPT_CONFFILE}"
        
        echo "Changes to ${NGINX_LETSENCRYPT_CONFFILE}"
        cat "${NGINX_LETSENCRYPT_CONFFILE}"
    fi
    
    service nginx restart
    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}
}

function install_letsencrypt {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    apt-get -yq install letsencrypt
    letsencrypt certonly --webroot -w /var/www/letsencrypt -d ${SERVER_DOMAIN_NAME} --rsa-key-size 4096
    
    # Diffie-Hellman-Parameters
    mkdir -p /etc/nginx/ssl
    echo "Generating Diffie-Hellman parameters. Using command:"
    echo "openssl dhparam -out /etc/nginx/ssl/dhparams.pem 4096"
    read -p "Press any key to start that command now. If that command returns fast rerun the above command as root on a shell!"
    openssl dhparam -out /etc/nginx/ssl/dhparams.pem 4096
    # access rights for certificate files
    chmod 600 /etc/letsencrypt/live/${SERVER_DOMAIN_NAME}/*.pem
    chmod 600 /etc/nginx/ssl/dhparams.pem
    
    # auto renew certificates within 90 days
    # using anacron as it doen't require the system to be running
    # at the exact time when the renew is scheduled
    ANACRON_LETSENCRYPT_RENEW="/etc/cron.monthly/letsencrypt-renew"
    echo "" >> "${ANACRON_LETSENCRYPT_RENEW}"
    chmod ugo+x "${ANACRON_LETSENCRYPT_RENEW}"
    echo "Changes to ${ANACRON_LETSENCRYPT_RENEW}"
    cat "${ANACRON_LETSENCRYPT_RENEW}"

    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}
}

function configure_nginx_nextcloud {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    # same as in step configure_nginx
    echo "server {" > "${NGINX_GATEWAY_CONFFILE}"
    echo "  listen 80 default_server;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  server_name ${SERVER_DOMAIN_NAME} ${LOCAL_IP} ${HOSTNAME};" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  root /var/www;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  location ^~ /.well-known/acme-challenge {" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      proxy_pass http://127.0.0.1:81;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      proxy_redirect off;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  }" >> "${NGINX_GATEWAY_CONFFILE}"
    # now changes for nextcloud
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  location / {" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      # Enforce HTTPS" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      # use this if you always want to redirect to the DynDNS address (no local access)." >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      return 301 https://\$server_name\$request_uri;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      #Use this if you also want to access the server by local IP:" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      #return 301 https://\$server_adr\$request_uri;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  }" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "}" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "server {" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  listen 443 ssl http2;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  server_name ${SERVER_DOMAIN_NAME} ${LOCAL_IP};" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  #" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # Configure SSL" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  #" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  ssl on;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # Certificates used" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  ssl_certificate /etc/letsencrypt/live/${SERVER_DOMAIN_NAME}/fullchain.pem;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  ssl_certificate_key /etc/letsencrypt/live/${SERVER_DOMAIN_NAME}/privkey.pem;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # Not using TLSv1 will break:" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  #   Android <= 4.4.40" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  #   IE <= 10" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  #   IE mobile <= 10" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # Removing TLSv1.1 breaks nothing else!" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  ssl_protocols TLSv1.2;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # Using the recommended cipher suite from: https://wiki.mozilla.org/Security/Server_Side_TLS" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK';" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # Diffie-Hellman parameter for DHE ciphersuites, recommended 2048 bits" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  ssl_dhparam /etc/nginx/ssl/dhparams.pem;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # Specifies a curve for ECDHE ciphers." >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # High security, but will not work with Chrome:" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  #ssl_ecdh_curve secp521r1;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # Works with Windows (Mobile), but not with Android (DavDroid):" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  #ssl_ecdh_curve secp384r1;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # Works with Android (DavDroid):" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  ssl_ecdh_curve prime256v1;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # Server should determine the ciphers, not the client" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  ssl_prefer_server_ciphers on;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # OCSP Stapling" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # fetch OCSP records from URL in ssl_certificate and cache them" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  ssl_stapling on;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  ssl_stapling_verify on;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  ssl_trusted_certificate /etc/letsencrypt/live/${SERVER_DOMAIN_NAME}/fullchain.pem;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  resolver ${LOCAL_GATEWAY};" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # SSL session handling" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  ssl_session_timeout 24h;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  ssl_session_cache shared:SSL:50m;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  ssl_session_tickets off;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  #" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # Add headers to serve security related headers" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  #  " >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # HSTS (ngx_http_headers_module is required)" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # In order to be recoginzed by SSL test, there must be an index.hmtl in the server's root" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  add_header Strict-Transport-Security \"max-age=63072000; includeSubdomains\" always;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  add_header X-Content-Type-Options \"nosniff\" always;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # Usually this should be \"DENY\", but when hosting sites using frames, it has to be \"SAMEORIGIN\"" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  add_header Referrer-Policy \"same-origin\" always;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  add_header X-XSS-Protection \"1; mode=block\" always;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  add_header X-Robots-Tag none;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  add_header X-Download-Options noopen;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  add_header X-Permitted-Cross-Domain-Policies none;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  location = / {" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      # Disable access to the web root, the Nextcloud subdir should be used instead." >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      deny all;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      # If you want to be able to access the cloud using the webroot only, use the following command instead:" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      # rewrite ^ /nextcloud;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  }" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  #" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  # Nextcloud" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  #" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  location ^~ /nextcloud {" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      # Set max. size of a request (important for uploads to Nextcloud)" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      client_max_body_size 10G;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      # Besides the timeout values have to be raised in nginx' Nextcloud config, these values have to be raised for the proxy as well" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      proxy_connect_timeout 3600;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      proxy_send_timeout 3600;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      proxy_read_timeout 3600;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      send_timeout 3600;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      proxy_buffering off;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      proxy_max_temp_file_size 10240m;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      proxy_set_header Host \$host;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      proxy_set_header X-Real-IP \$remote_addr;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      proxy_pass http://127.0.0.1:82;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "      proxy_redirect off;" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "  }" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "}" >> "${NGINX_GATEWAY_CONFFILE}"
    echo "Changes to ${NGINX_GATEWAY_CONFFILE}"
    cat "${NGINX_GATEWAY_CONFFILE}"

    echo "upstream php-handler {" > "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  server unix:/run/php/php7.0-fpm.sock;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "}" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "server {" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  listen 82;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  server_name 127.0.0.1;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  # Add headers to serve security related headers" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  # Use 'proxy_set_header' (not 'add_header') as the headers have to be passed through a proxy." >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  proxy_set_header Strict-Transport-Security \"max-age=15768000; includeSubDomains; always;\";" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  proxy_set_header X-Content-Type-Options \"nosniff; always;\";" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  proxy_set_header X-XSS-Protection \"1; mode=block; always;\";" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  proxy_set_header X-Robots-Tag none;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  proxy_set_header X-Download-Options noopen;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  proxy_set_header X-Permitted-Cross-Domain-Policies none;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  # Path to the root of your installation" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  root /var/www/;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  location = /robots.txt {" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      allow all;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      log_not_found off;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      access_log off;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  }" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  # The following 2 rules are only needed for the user_webfinger app." >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  # Uncomment it if you're planning to use this app." >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  #rewrite ^/.well-known/host-meta /nextcloud/public.php?service=host-meta last;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  #rewrite ^/.well-known/host-meta.json /nextcloud/public.php?service=host-meta-json last;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  location = /.well-known/carddav { " >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      return 301 \$scheme://\$host/nextcloud/remote.php/dav;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  }" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  location = /.well-known/caldav { " >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      return 301 \$scheme://\$host/nextcloud/remote.php/dav;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  }" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  location /.well-known/acme-challenge { }" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  location ^~ /nextcloud {" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      # set max upload size" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      client_max_body_size 10G;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      fastcgi_buffers 64 4K;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      # Enable gzip but do not remove ETag headers" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      gzip on;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      gzip_vary on;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      gzip_comp_level 4;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      gzip_min_length 256;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      # Uncomment if your server is build with the ngx_pagespeed module" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      # This module is currently not supported." >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      #pagespeed off;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      location /nextcloud {" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          rewrite ^ /nextcloud/index.php\$uri;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      }" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      location ~ ^/nextcloud/(?:build|tests|config|lib|3rdparty|templates|data)/ {" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          deny all;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      }" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      location ~ ^/nextcloud/(?:\.|autotest|occ|issue|indie|db_|console) {" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          deny all;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      }" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      location ~ ^/nextcloud/(?:index|remote|public|cron|core/ajax/update|status|ocs/v[12]|updater/.+|ocs-provider/.+|core/templates/40[34])\.php(?:\$|/) {" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          include fastcgi_params;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          fastcgi_split_path_info ^(.+\.php)(/.+)\$;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          fastcgi_param PATH_INFO \$fastcgi_path_info;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          # Avoid sending the security headers twice" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          fastcgi_param modHeadersAvailable true;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          fastcgi_param front_controller_active true;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          fastcgi_pass php-handler;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          fastcgi_intercept_errors on;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          # Raise timeout values." >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          # This is especially important when the Nextcloud setup runs into timeouts (504 gateway errors)" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          fastcgi_read_timeout 600;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          fastcgi_send_timeout 600;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          fastcgi_connect_timeout 600;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          fastcgi_request_buffering off;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          # Pass PHP variables directly to PHP." >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          # This is usually done in the php.ini. For more flexibility, these variables are configured in the nginx config." >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          # All the PHP parameters have to be set in one fastcgi_param. When using more 'fastcgi_param PHP_VALUE' directives, the last one will override all the others." >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          fastcgi_param PHP_VALUE \"open_basedir=/var/www:/tmp/:/var/nextcloud_data:/dev/urandom:/proc/meminfo" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          upload_max_filesize = 10G" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          post_max_size = 10G" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          max_execution_time = 3600" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          output_buffering = off\";" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          # Make sure that the real IP of the remote host is passed to PHP." >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          fastcgi_param REMOTE_ADDR \$http_x_real_ip;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      }" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      location ~ ^/nextloud/(?:updater|ocs-provider)(?:\$|/) {" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          try_files \$uri/ =404;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          index index.php;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      }" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      # Adding the cache control header for js and css files" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      # Make sure it is BELOW the PHP block" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      location ~* \.(?:css|js)\$ {" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          try_files \$uri /nextcloud/index.php\$uri\$is_args\$args;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          proxy_set_header Cache-Control \"public, max-age=7200\";" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          # Add headers to serve security related headers" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          # Again use 'proxy_set_header' (not 'add_header') as the headers have to be passed through a proxy." >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          proxy_set_header Strict-Transport-Security \"max-age=15768000; includeSubDomains; preload;\";" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          proxy_set_header X-Content-Type-Options nosniff;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          #proxy_set_header X-Frame-Options \"SAMEORIGIN\";" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          proxy_set_header X-XSS-Protection \"1; mode=block\";" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          proxy_set_header X-Robots-Tag none;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          proxy_set_header X-Download-Options noopen;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          proxy_set_header X-Permitted-Cross-Domain-Policies none;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          # Optional: Don't log access to assets" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          access_log off;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      }" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      location ~* \.(?:svg|gif|png|html|ttf|woff|ico|jpg|jpeg)\$ {" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          try_files \$uri /nextcloud/index.php\$uri\$is_args\$args;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          # Optional: Don't log access to other assets" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "          access_log off;" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "      }" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "  }" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "}" >> "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "Changes to ${NGINX_NEXTCLOUD_CONFFILE}"
    cat "${NGINX_NEXTCLOUD_CONFFILE}"

    nginx -t
    read -p "Please check previous two lines, if nginx configuration test was successful. Press CTRL+C now, to abort the script or any key to continue..."

    service nginx restart

    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}
}

function install_nextcloud {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    echo "Please visit https://nextcloud.com/install/#instructions-server and download recent tar.bz2."
    echo "Save the archive to ${SCRIPT_DIR}."
    read -p "When finished press any key to continue."
    cd "${SCRIPT_DIR}"
    NEXTCLOUD_ARCHIVE=`ls -1 nextcloud-*.tar.bz2 2> /dev/null`
    echo ">${NEXTCLOUD_ARCHIVE}<"
    if [ -z "$NEXTCLOUD_ARCHIVE" ]; then
        echo "No nextcloud-*.tar.bz2 found. Aborting installation."
        exit 1
    fi
    echo "Stopping nginx now for security reasons. Once the archive is extracted, nexcloud will be available on the public internet. But you have not configured a nextcloud administrator yet. It might be possible that some is calling your server and is faster than you."
    read -p "Press any key to stop nginx and extract nextcloud archive now..."
    service nginx stop
    tar -xjf ${NEXTCLOUD_ARCHIVE} -C /var/www
    rm ${NEXTCLOUD_ARCHIVE}
    chown -R www-data:www-data /var/www/nextcloud
    chown -R www-data:www-data /var/nextcloud_data
    
    echo "You have to enter the following five commands in mariadb console (choose a different password in second command!)."
    echo "create database nextcloud_db;"
    echo "create user nextcloud_db_user@localhost identified by 'MeInPasSw0rT';"
    echo "grant all privileges on nextcloud_db.* to nextcloud_db_user@localhost;"
    echo "flush privileges;"
    echo "exit;"
    read -p "Press any key to start mariadb console now..."
    mysql -u root -p

    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}
}

function configure_nextcloud {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    # make sure /var/nextcloud_data is pointing to mount point with fstab user privileges
    umount ${VIRTUALBOX_SHARED_FOLDER_NAME_NEXTCLOUD_DATA}
    mount ${VIRTUALBOX_SHARED_FOLDER_NAME_NEXTCLOUD_DATA}
    
    # config.php is created when the website is called for the first time
    echo "When setting up nextcloud, please use those values:"
    echo "data directory: /var/nextcloud_data"
    echo "database user: nextcloud_db_user"
    echo "database: nextcloud_db"
    echo "database server: localhost:3306"
    read -p "Press any key to start nginx again. You should IMMEDIATELY CALL https://${SERVER_DOMAIN_NAME}/nextcloud and configure the administrator account!"
    service nginx start
    read -p "Logout of nextcloud. Press any key to proceed with further configuration..."

    NEXTCLOUD_CONFIG="/var/www/nextcloud/config/config.php"
    # make a backup if not done before
    if [ ! -f "${NEXTCLOUD_CONFIG}.original" ]; then
        cp "${NEXTCLOUD_CONFIG}" "${NEXTCLOUD_CONFIG}.original"
    else
        cp "${NEXTCLOUD_CONFIG}.original" "${NEXTCLOUD_CONFIG}"
    fi
    sed -i -e "/  'installed' => true,/c\  'installed' => true,\n  'memcache.local' => '\\\OC\\\Memcache\\\APCu',\n  'overwriteprotocol' => 'https',\n  'logtimezone' => 'Europe/Berlin'," "${NEXTCLOUD_CONFIG}"
    sed -i -e "/    0 => '${SERVER_DOMAIN_NAME}',/c\    0 => '${SERVER_DOMAIN_NAME}',\n    1 => '${LOCAL_IP}'," "${NEXTCLOUD_CONFIG}"
    echo "Changes to ${NEXTCLOUD_CONFIG}"
    diff "${NEXTCLOUD_CONFIG}.original" "${NEXTCLOUD_CONFIG}" | grep -e '^>'
    
    service nginx restart

    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}
}

function final_configuration_nextcloud {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    echo "Setting up a cron job for regular clean up task. Please add the following line in the crontab editor:"
    echo "*/15  *  *  *  * php -f /var/www/nextcloud/cron.php"
    read -p "Press any key to edit crontab now..."
    crontab -u www-data -e
    read -p "In nextcloud administration 'Cron' switch from AJAX to CRON now. Press any key to continue..."

    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}
}

function install_fail2ban {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    apt-get -yq install fail2ban
    FAIL2BAN_FILTER="/etc/fail2ban/filter.d/nextcloud.conf"
    FAIL2BAN_FILTER_CONTENT="[Definition]
failregex=^{\"reqId\":\".*\",\"remoteAddr\":\".*\",\"app\":\"core\",\"message\":\"Login failed: '.*' \(Remote IP: '<HOST>'\)\",\"level\":2,\"time\":\".*\"}$
            ^{\"reqId\":\".*\",\"level\":2,\"time\":\".*\",\"remoteAddr\":\".*\",\"app\":\"core\".*\",\"message\":\"Login failed: '.*' \(Remote IP: '<HOST>'\)\".*}$"
    echo "${FAIL2BAN_FILTER_CONTENT}" > "${FAIL2BAN_FILTER}"
    
    FAIL2BAN_JAIL="/etc/fail2ban/jail.local"
    FAIL2BAN_JAIL_CONTENT="[nextcloud]
enabled=true
port=80,443
protocol=tcp
filter=nextcloud
maxretry=3
bantime=1800
logpath=/var/nextcloud_data/nextcloud.log"
    echo "${FAIL2BAN_JAIL_CONTENT}" > "${FAIL2BAN_JAIL}"

    NEXTCLOUD_CONFIG="/var/www/nextcloud/config/config.php"
    # make a backup if not done before
    if [ ! -f "${NEXTCLOUD_CONFIG}.beforeFail2Ban" ]; then
        cp "${NEXTCLOUD_CONFIG}" "${NEXTCLOUD_CONFIG}.beforeFail2Ban"
    else
        cp "${NEXTCLOUD_CONFIG}.beforeFail2Ban" "${NEXTCLOUD_CONFIG}"
    fi
    sed -i -e "/  'installed' => true,/c\  'installed' => true,\n  'auth.bruteforce.protection.enabled' => 'false'," "${NEXTCLOUD_CONFIG}"
    echo "Changes to ${NEXTCLOUD_CONFIG}"
    diff "${NEXTCLOUD_CONFIG}.beforeFail2Ban" "${NEXTCLOUD_CONFIG}" | grep -e '^>'

    service nginx restart
    service fail2ban restart

    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}
}

update_vim_dkms_ssh
vbox_additions
install_nginx
install_mariadb
install_php
configure_php
configure_mariadb
configure_nginx
install_letsencrypt
configure_nginx_nextcloud
install_nextcloud
configure_nextcloud
final_configuration_nextcloud
install_fail2ban

cd "${CURRENT_DIR}"

echo "Installation and configuration of nextcloud is finished."
