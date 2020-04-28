#!/bin/bash
# Bash install script for nextcloud server in VirtualBox guest with SSL and 
# nginx as subdir in dyndns domain and nextcloud_data dir linked to a shared folder.
#
# The script follows the description on that awesome guide:
# https://decatec.de/home-server/nextcloud-auf-ubuntu-server-mit-nginx-mariadb-php-lets-encrypt-redis-und-fail2ban/
# But it also utilizes
# https://unix.stackexchange.com/a/345518
# https://unix.stackexchange.com/questions/335609/how-to-mount-shared-folder-from-virtualbox-at-boot-time-in-debian
# https://www.freedesktop.org/software/systemd/man/systemd.mount.html
#
# Original author of that script: Robert Wloch (robert@rowlo.de)

SERVER_DOMAIN_NAME="your-dyndns-domain.com"
VIRTUALBOX_SHARED_FOLDER_NAME_NEXTCLOUD_DATA="cloud-data"
MOUNTPOINTVBOXFS="/media/sfclouddata"
PHP_VERSION="7.4"
MCRYPT_VERSION="1.0.3"

NGINX_GATEWAY_CONFFILE="/etc/nginx/conf.d/${SERVER_DOMAIN_NAME}.conf"
NGINX_LETSENCRYPT_CONFFILE="/etc/nginx/conf.d/${SERVER_DOMAIN_NAME}_letsencrypt.conf"
NGINX_NEXTCLOUD_CONFFILE="/etc/nginx/conf.d/${SERVER_DOMAIN_NAME}_nextcloud.conf"

# https://unix.stackexchange.com/a/345518
SYSTEMD_MOUNT_UNIT_NAME=`systemd-escape -p --suffix=mount "${MOUNTPOINTVBOXFS}"`
# https://unix.stackexchange.com/questions/335609/how-to-mount-shared-folder-from-virtualbox-at-boot-time-in-debian
# https://www.freedesktop.org/software/systemd/man/systemd.mount.html
SYSTEMD_MOUNT="/lib/systemd/system/${SYSTEMD_MOUNT_UNIT_NAME}"
SYSTEMD_MOUNT_LINK="/etc/systemd/system/multi-user.target.wants/${SYSTEMD_MOUNT_UNIT_NAME}"

CURRENT_DIR=`pwd`
SCRIPT_DIR=`dirname "$(realpath $0)"`
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
    apt-get -yq install vim dkms build-essential module-assistant openssh-server
    m-a prepare
    
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
    mkdir -p "${MOUNTPOINTVBOXFS}"
    chown www-data:www-data "${MOUNTPOINTVBOXFS}"
    ln -s "${MOUNTPOINTVBOXFS}/nextcloud_data" /var/nextcloud_data

    WWWDATA_UID=`cat /etc/passwd | grep www-data | cut -d ':' -f 3`
    WWWDATA_GID=`cat /etc/group | grep www-data | cut -d ':' -f 3`
    touch "${SYSTEMD_MOUNT}"
    ln -s "${SYSTEMD_MOUNT}" "${SYSTEMD_MOUNT_LINK}"
    echo "[Unit]
Requires=vboxadd-service.service
After=vboxadd-service.service

[Mount]
What=${VIRTUALBOX_SHARED_FOLDER_NAME_NEXTCLOUD_DATA}
Where=${MOUNTPOINTVBOXFS}
Type=vboxsf
Options=umask=0007,uid=${WWWDATA_UID},gid=${WWWDATA_GID}

[Install]
WantedBy = multi-user.target
" > "${SYSTEMD_MOUNT}"

    read -p "Please insert the VirtualBox GuestAddtions and mount the drive now. When ready, press any key to continue..."
    VBOXADDITIONS=`ls /media/${SUDO_USER}/ | grep VBox_GAs`
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

    apt-get -yq install php${PHP_VERSION}-fpm php${PHP_VERSION}-gd php${PHP_VERSION}-mysql php${PHP_VERSION}-curl php${PHP_VERSION}-xml php${PHP_VERSION}-zip php${PHP_VERSION}-intl php${PHP_VERSION}-mbstring php${PHP_VERSION}-bz2 php-apcu php-imagick
    # https://github.com/s3inlc/hashtopolis/issues/373
    apt install libmcrypt-dev php${PHP_VERSION}-dev
    read -p "The following build might prompt for a libmcrypt prefix. Just press enter and go with the default."
    pecl install mcrypt-${MCRYPT_VERSION}

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
    WWW_CONF="/etc/php/${PHP_VERSION}/fpm/pool.d/www.conf"
    if [ ! -f "${WWW_CONF}.original" ]; then
        cp "${WWW_CONF}" "${WWW_CONF}.original"
    else
        cp "${WWW_CONF}.original" "${WWW_CONF}"
    fi
    sed -i -e '/^user =/c\user = www-data' "${WWW_CONF}"
    sed -i -e '/^group =/c\group = www-data' "${WWW_CONF}"
    # enable socket configuration
    sed -i -e "/^listen =/c\listen = \/run\/php\/php${PHP_VERSION}-fpm.sock" "${WWW_CONF}"
    # enable env entries (required by nextcloud
    sed -i -e 's/;env\[/env\[/g' "${WWW_CONF}"
    echo "Changes to ${WWW_CONF}"
    diff "${WWW_CONF}.original" "${WWW_CONF}" | grep -e '^>'

    # change global php settings
    PHP_INI="/etc/php/${PHP_VERSION}/fpm/php.ini"
    if [ ! -f "${PHP_INI}.original" ]; then
        cp "${PHP_INI}" "${PHP_INI}.original"
    else
        cp "${PHP_INI}.original" "${PHP_INI}"
    fi
    sed -i -e '/^;cgi.fix_pathinfo =/c\cgi.fix_pathinfo = 0' "${PHP_INI}"
    sed -i -e '/^cgi.fix_pathinfo =/c\cgi.fix_pathinfo = 0' "${PHP_INI}"
    sed -i -e '/^;open_basedir =/c\open_basedir = \/var\/www\/:\/tmp\/' "${PHP_INI}"
    sed -i -e '/^open_basedir =/c\open_basedir = \/var\/www\/:\/tmp\/' "${PHP_INI}"
    sed -i -e '/^;opcache.enable =/c\opcache.enable = 1' "${PHP_INI}"
    sed -i -e '/^opcache.enable =/c\opcache.enable = 1' "${PHP_INI}"
    sed -i -e '/^;opcache.enable_cli =/c\opcache.enable_cli = 1' "${PHP_INI}"
    sed -i -e '/^opcache.enable_cli =/c\opcache.enable_cli = 1' "${PHP_INI}"
    sed -i -e '/^;opcache.memory_consumption =/c\opcache.memory_consumption = 128' "${PHP_INI}"
    sed -i -e '/^opcache.memory_consumption =/c\opcache.memory_consumption = 128' "${PHP_INI}"
    sed -i -e '/^;opcache.interned_strings_buffer =/c\opcache.interned_strings_buffer = 8' "${PHP_INI}"
    sed -i -e '/^opcache.interned_strings_buffer =/c\opcache.interned_strings_buffer = 8' "${PHP_INI}"
    sed -i -e '/^;opcache.max_accelerated_files =/c\opcache.max_accelerated_files = 10000' "${PHP_INI}"
    sed -i -e '/^opcache.max_accelerated_files =/c\opcache.max_accelerated_files = 10000' "${PHP_INI}"
    sed -i -e '/^;opcache.revalidate_freq =/c\opcache.revalidate_freq = 1' "${PHP_INI}"
    sed -i -e '/^opcache.revalidate_freq =/c\opcache.revalidate_freq = 1' "${PHP_INI}"
    sed -i -e '/^;opcache.save_comments =/c\opcache.save_comments = 1' "${PHP_INI}"
    sed -i -e '/^opcache.save_comments =/c\opcache.save_comments = 1' "${PHP_INI}"
    sed -i -e '/^memory_limit =/c\memory_limit = -1' "${PHP_INI}"
    sed -i -e '/^;extension=xsl/c\;extension=xsl\nextension=mcrypt.so' "${PHP_INI}"
    echo "Changes to ${PHP_INI}"
    diff "${PHP_INI}.original" "${PHP_INI}" | grep -e '^>'

    # prepare chron job
    CLI_PHP_INI="/etc/php/${PHP_VERSION}/cli/php.ini"
    if [ ! -f "${CLI_PHP_INI}.original" ]; then
        cp "${CLI_PHP_INI}" "${CLI_PHP_INI}.original"
    else
        cp "${CLI_PHP_INI}.original" "${CLI_PHP_INI}"
    fi
    sed -i -e '/^;cgi.fix_pathinfo =/c\cgi.fix_pathinfo = 0' "${CLI_PHP_INI}"
    sed -i -e '/^cgi.fix_pathinfo =/c\cgi.fix_pathinfo = 0' "${CLI_PHP_INI}"
    sed -i -e '/^;open_basedir =/c\open_basedir = \/var\/www\/:\/tmp\/:\/var\/nextcloud_data\/' "${CLI_PHP_INI}"
    sed -i -e '/^open_basedir =/c\open_basedir = \/var\/www\/:\/tmp\/:\/var\/nextcloud_data\/' "${CLI_PHP_INI}"
    echo "Changes to ${CLI_PHP_INI}"
    diff "${CLI_PHP_INI}.original" "${CLI_PHP_INI}" | grep -e '^>'

    service php${PHP_VERSION}-fpm restart
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

    # make sure the shared folder is mounted
    systemctl start ${SYSTEMD_MOUNT_UNIT_NAME}

    # modify global configuration
    NGINX_CONF="/etc/nginx/nginx.conf"
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
        echo "server {
  listen 80 default_server;
  server_name ${SERVER_DOMAIN_NAME} ${LOCAL_IP} ${HOSTNAME};

  root /var/www;

  location ^~ /.well-known/acme-challenge {
      proxy_pass http://127.0.0.1:81;
      proxy_redirect off;
  }
}" >> "${NGINX_GATEWAY_CONFFILE}"

        echo "Changes to ${NGINX_GATEWAY_CONFFILE}"
        cat "${NGINX_GATEWAY_CONFFILE}"
    fi

    if [ ! -f "${NGINX_LETSENCRYPT_CONFFILE}" ]; then
        touch "${NGINX_LETSENCRYPT_CONFFILE}"
        echo "server {
  listen 127.0.0.1:81;
  server_name 127.0.0.1;

  location ^~ /.well-known/acme-challenge {
      default_type text/plain;
      root /var/www/letsencrypt;
  }
}" >> "${NGINX_LETSENCRYPT_CONFFILE}"
        
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

    # make sure the shared folder is mounted
    systemctl start ${SYSTEMD_MOUNT_UNIT_NAME}

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
    echo "#!/bin/sh
date >> /var/log/letsencrypt-renew.log
letsencrypt renew >> /var/log/letsencrypt-renew.log && service nginx restart > /dev/null 2>&1" >> "${ANACRON_LETSENCRYPT_RENEW}"
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

    # make sure the shared folder is mounted
    systemctl start ${SYSTEMD_MOUNT_UNIT_NAME}

    # same as in step configure_nginx
    echo "server {
  listen 80 default_server;
  server_name ${SERVER_DOMAIN_NAME} ${LOCAL_IP} ${HOSTNAME};

  root /var/www;

  location ^~ /.well-known/acme-challenge {
      proxy_pass http://127.0.0.1:81;
      proxy_redirect off;
  }
  # now changes for nextcloud

  location / {
      # Enforce HTTPS
      # use this if you always want to redirect to the DynDNS address (no local access).
      return 301 https://\$server_name\$request_uri;

      #Use this if you also want to access the server by local IP:
      #return 301 https://\$server_adr\$request_uri;
  }
}

server {
  listen 443 ssl http2;
  server_name ${SERVER_DOMAIN_NAME} ${LOCAL_IP};

  #
  # Configure SSL (deprecated in >= Kubuntu 20.04 LTS)
  #
  #ssl on;

  # Certificates used
  ssl_certificate /etc/letsencrypt/live/${SERVER_DOMAIN_NAME}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${SERVER_DOMAIN_NAME}/privkey.pem;

  # Not using TLSv1 will break:
  #   Android <= 4.4.40
  #   IE <= 10
  #   IE mobile <= 10
  # Removing TLSv1.1 breaks nothing else!
  ssl_protocols TLSv1.2;

  # Using the recommended cipher suite from: https://wiki.mozilla.org/Security/Server_Side_TLS
  ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK';

  # Diffie-Hellman parameter for DHE ciphersuites, recommended 2048 bits
  ssl_dhparam /etc/nginx/ssl/dhparams.pem;

  # Specifies a curve for ECDHE ciphers.
  # High security, but will not work with Chrome:
  #ssl_ecdh_curve secp521r1;
  # Works with Windows (Mobile), but not with Android (DavDroid):
  #ssl_ecdh_curve secp384r1;
  # Works with Android (DavDroid):
  ssl_ecdh_curve prime256v1;

  # Server should determine the ciphers, not the client
  ssl_prefer_server_ciphers on;

  # OCSP Stapling
  # fetch OCSP records from URL in ssl_certificate and cache them
  ssl_stapling on;
  ssl_stapling_verify on;
  ssl_trusted_certificate /etc/letsencrypt/live/${SERVER_DOMAIN_NAME}/fullchain.pem;
  resolver ${LOCAL_GATEWAY};

  # SSL session handling
  ssl_session_timeout 24h;
  ssl_session_cache shared:SSL:50m;
  ssl_session_tickets off;

  #
  # Add headers to serve security related headers
  #
  # HSTS (ngx_http_headers_module is required)
  # In order to be recoginzed by SSL test, there must be an index.hmtl in the server's root
  add_header Strict-Transport-Security \"max-age=63072000; includeSubdomains\" always;
  add_header X-Content-Type-Options \"nosniff\" always;
  # Usually this should be \"DENY\", but when hosting sites using frames, it has to be \"SAMEORIGIN\"
  add_header X-Frame-Options \"SAMEORIGIN\" always;
  add_header Referrer-Policy \"same-origin\" always;
  add_header X-XSS-Protection \"1; mode=block\" always;
  add_header X-Robots-Tag none;
  add_header X-Download-Options noopen;
  add_header X-Permitted-Cross-Domain-Policies none;

  location = / {
      # Disable access to the web root, the Nextcloud subdir should be used instead.
      deny all;

      # If you want to be able to access the cloud using the webroot only, use the following command instead:
      # rewrite ^ /nextcloud;
  }

  #
  # Nextcloud
  #
  location ^~ /nextcloud {
      # Set max. size of a request (important for uploads to Nextcloud)
      client_max_body_size 10G;
      # Besides the timeout values have to be raised in nginx' Nextcloud config, these values have to be raised for the proxy as well
      proxy_connect_timeout 3600;
      proxy_send_timeout 3600;
      proxy_read_timeout 3600;
      send_timeout 3600;
      proxy_buffering off;
      proxy_max_temp_file_size 10240m;
      proxy_set_header Host \$host;
      proxy_set_header X-Real-IP \$remote_addr;
      proxy_pass http://127.0.0.1:82;
      proxy_redirect off;
  }
}" > "${NGINX_GATEWAY_CONFFILE}"
    echo "Changes to ${NGINX_GATEWAY_CONFFILE}"
    cat "${NGINX_GATEWAY_CONFFILE}"

    echo "upstream php-handler {
  server unix:/run/php/php${PHP_VERSION}-fpm.sock;
}

server {
  listen 82;
  server_name 127.0.0.1;

  # Add headers to serve security related headers
  # Use 'proxy_set_header' (not 'add_header') as the headers have to be passed through a proxy.
  proxy_set_header Strict-Transport-Security \"max-age=15768000; includeSubDomains; always;\";
  proxy_set_header X-Content-Type-Options \"nosniff; always;\";
  proxy_set_header X-XSS-Protection \"1; mode=block; always;\";
  proxy_set_header X-Robots-Tag none;
  proxy_set_header X-Download-Options noopen;
  proxy_set_header X-Permitted-Cross-Domain-Policies none;

  # Path to the root of your installation
  root /var/www/;

  location = /robots.txt {
      allow all;
      log_not_found off;
      access_log off;
  }

  # The following 2 rules are only needed for the user_webfinger app.
  # Uncomment it if you're planning to use this app.
  #rewrite ^/.well-known/host-meta /nextcloud/public.php?service=host-meta last;
  #rewrite ^/.well-known/host-meta.json /nextcloud/public.php?service=host-meta-json last;

  location = /.well-known/carddav {
      return 301 \$scheme://\$host/nextcloud/remote.php/dav;
  }

  location = /.well-known/caldav {
      return 301 \$scheme://\$host/nextcloud/remote.php/dav;
  }

  location /.well-known/acme-challenge { }

  location ^~ /nextcloud {
      # set max upload size
      client_max_body_size 10G;
      fastcgi_buffers 64 4K;

      # Enable gzip but do not remove ETag headers
      gzip on;
      gzip_vary on;
      gzip_comp_level 4;
      gzip_min_length 256;
      gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
      gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;

      # Uncomment if your server is build with the ngx_pagespeed module
      # This module is currently not supported.
      #pagespeed off;

      location /nextcloud {
          rewrite ^ /nextcloud/index.php\$uri;
      }

      location ~ ^/nextcloud/(?:build|tests|config|lib|3rdparty|templates|data)/ {
          deny all;
      }

      location ~ ^/nextcloud/(?:\.|autotest|occ|issue|indie|db_|console) {
          deny all;
      }

      location ~ ^/nextcloud/(?:index|remote|public|cron|core/ajax/update|status|ocs/v[12]|updater/.+|ocs-provider/.+|core/templates/40[34])\.php(?:\$|/) {
          include fastcgi_params;
          fastcgi_split_path_info ^(.+\.php)(/.+)\$;
          fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
          fastcgi_param PATH_INFO \$fastcgi_path_info;
          # Avoid sending the security headers twice
          fastcgi_param modHeadersAvailable true;
          fastcgi_param front_controller_active true;
          fastcgi_pass php-handler;
          fastcgi_intercept_errors on;

          # Raise timeout values.
          # This is especially important when the Nextcloud setup runs into timeouts (504 gateway errors)
          fastcgi_read_timeout 600;
          fastcgi_send_timeout 600;
          fastcgi_connect_timeout 600;
          fastcgi_request_buffering off;

          # Pass PHP variables directly to PHP.
          # This is usually done in the php.ini. For more flexibility, these variables are configured in the nginx config.
          # All the PHP parameters have to be set in one fastcgi_param. When using more 'fastcgi_param PHP_VALUE' directives, the last one will override all the others.
          fastcgi_param PHP_VALUE \"open_basedir=/var/www:/tmp/:/var/nextcloud_data:/dev/urandom:/proc/meminfo
          upload_max_filesize = 10G
          post_max_size = 10G
          max_execution_time = 3600
          output_buffering = off\";

          # Make sure that the real IP of the remote host is passed to PHP.
          fastcgi_param REMOTE_ADDR \$http_x_real_ip;
      }

      location ~ ^/nextcloud/(?:updater|ocs-provider)(?:\$|/) {
          try_files \$uri/ =404;
          index index.php;
      }

      # Adding the cache control header for js and css files
      # Make sure it is BELOW the PHP block
      location ~* \.(?:css|js)\$ {
          try_files \$uri /nextcloud/index.php\$uri\$is_args\$args;
          proxy_set_header Cache-Control \"public, max-age=7200\";
          # Add headers to serve security related headers
          # Again use 'proxy_set_header' (not 'add_header') as the headers have to be passed through a proxy.
          proxy_set_header Strict-Transport-Security \"max-age=15768000; includeSubDomains; preload;\";
          proxy_set_header X-Content-Type-Options nosniff;
          #proxy_set_header X-Frame-Options \"SAMEORIGIN\";
          proxy_set_header X-XSS-Protection \"1; mode=block\";
          proxy_set_header X-Robots-Tag none;
          proxy_set_header X-Download-Options noopen;
          proxy_set_header X-Permitted-Cross-Domain-Policies none;
          # Optional: Don't log access to assets
          access_log off;
      }

      location ~* \.(?:svg|gif|png|html|ttf|woff|ico|jpg|jpeg)\$ {
          try_files \$uri /nextcloud/index.php\$uri\$is_args\$args;
          # Optional: Don't log access to other assets
          access_log off;
      }
  }
}" > "${NGINX_NEXTCLOUD_CONFFILE}"
    echo "Changes to ${NGINX_NEXTCLOUD_CONFFILE}"
    cat "${NGINX_NEXTCLOUD_CONFFILE}"

    nginx -t
    read -p "Please check previous two lines, if nginx configuration test was successful. Press CTRL+C now, to abort the script or any key to continue..."

    service nginx restart

    read -p "A reboot is required before installing nextcloud so that systemd does a clean run through php initialization. Press any key to reboot."

    cd "${SCRIPT_DIR}"
    touch FINISHED.${SCRIPT}.${FUNCNAME[0]}

    reboot
}

function install_nextcloud {
    cd "${SCRIPT_DIR}"
    FINISHED_FILE="FINISHED.${SCRIPT}.${FUNCNAME[0]}"
    if [ -e "${FINISHED_FILE}" ]; then
        echo "File exists: ${FINISHED_FILE}. Skipping step ${FUNCNAME[0]}."
        return
    fi
    echo "Step: ${FUNCNAME[0]}"

    # make sure the shared folder is mounted
    systemctl start ${SYSTEMD_MOUNT_UNIT_NAME}

    echo "Please visit https://nextcloud.com/install/#instructions-server and download the recent tar.bz2."
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
    systemctl start ${SYSTEMD_MOUNT_UNIT_NAME}
    SYSD_MOUNT="$(echo ${MOUNTPOINTVBOXFS} | cut -f 2 -d '/')-$(echo ${MOUNTPOINTVBOXFS} | cut -f 3 -d '/')"

    # Creating a status.sh script next to install_nc.sh that allows to health check shared folder mount status
    echo "#!/bin/sh
systemctl status ${SYSD_MOUNT}.mount | grep Active
service nginx status | grep Active
" > status.sh
    chmod u+x status.sh

    CHECK=$(systemctl status ${SYSD_MOUNT}.mount | grep "active (mounted)")
    if [ ! -z "${CHECK}" ]; then
        echo "Shared folder ${MOUNTPOINTVBOXFS} is active."
    else
        echo "Shared folder ${MOUNTPOINTVBOXFS} is NOT ACTIVE. Aborting installation to protect you from wrong nextcloud data location."
        exit 1
    fi
    
    # config.php is created when the website is called for the first time
    echo "When setting up nextcloud, please use those values:"

    # Due to a bug in nextcloud symlinks are currently not working.
    # See and follow: https://github.com/nextcloud/server/issues/11879
    # Workaround applied is taken from: https://help.nextcloud.com/t/new-users-fail-first-login-dont-get-default-files-following-symlinks-is-not-allowed/45755/5
    #echo "data directory: /var/nextcloud_data"
    echo "data directory: ${MOUNTPOINTVBOXFS}/nextcloud_data"

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
    touch "/var/nextcloud_data/nextcloud.log"

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
