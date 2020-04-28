# installnc
A script that automates installation of nextcloud on (k)ubuntu 20.04 LTS running in a VirtualBox guest.

It's a bash script for installing a nextcloud server in a VirtualBox guest with letsencrypt SSL and nginx as subdir in dyndns domain and nextcloud_data dir linked to a shared folder.
The script follows the description provided with that **awesome guide** [German]:
[Nextcloud auf Ubuntu Server mit nginx, MariaDB, PHP, Let’s Encrypt, Redis und Fail2ban](https://decatec.de/home-server/nextcloud-auf-ubuntu-server-mit-nginx-mariadb-php-lets-encrypt-redis-und-fail2ban/ "Nextcloud auf Ubuntu Server mit nginx, MariaDB, PHP, Let’s Encrypt, Redis und Fail2ban")

Additionally it also utilizes
* [Unix & Linux Stack Exchange answer on Systemd mount fails. Where= setting doesn't match unit name](https://unix.stackexchange.com/a/345518 "Unix & Linux Stack Exchange answer on Systemd mount fails. Where= setting doesn't match unit name")
* [Unix & Linux Stack Exchange: How to mount shared folder from VirtualBox at boot time in Debian](https://unix.stackexchange.com/questions/335609/how-to-mount-shared-folder-from-virtualbox-at-boot-time-in-debian "Unix & Linux Stack Exchange: How to mount shared folder from VirtualBox at boot time in Debian")
* [systemd.mount — Mount unit configuration](https://www.freedesktop.org/software/systemd/man/systemd.mount.html "systemd.mount — Mount unit configuration")


## Original author of install_nc.sh script
[Robert Wloch](https://github.com/rowlo "Robert Wloch on github")

## Prerequisites:
* Setup a dynamic dns domain in your router and configure port mapping to :80 (TCP, http) and :443 (TCP, https) to your virtual machine.

## Usage:
1. Modify the top three variables of the install_nc.sh script to match your needs:
    - SERVER_DOMAIN_NAME="your-dyndns-domain.com"
    - VIRTUALBOX_SHARED_FOLDER_NAME_NEXTCLOUD_DATA="cloud-data"
    - MOUNTPOINTVBOXFS="/media/sfclouddata"
2. Prepare a shared folder for your cloud data. If you like, put it in an encrypted container and mount it, e.g. "/media/truecrypt2/cloud-data/nextcloud_data/"
  In the example truecrypt2 is an ext4 file container, "cloud-data" is the shared folder , and "nextcloud_data" is the nextcloud data folder with changable permissions from within the guest.
3. In VirtualBox create a guest from a [kubuntu-20.04-desktop-amd64.iso](http://cdimage.ubuntu.com/kubuntu/releases/20.04/release/ "kubuntu-20.04-desktop-amd64.iso") and configure the shared folder. Stick to "cloud_data" if you like.
4. Copy that script into your guest OS to /root/bin/ and make it excutable to root.
5. Acquire a root shell, e.g. by: sudo /bin/bash
6. Keep executing the script until it prints "Installation and configuration of nextcloud is finished."
  The script will cause a reboot if required but will prompt to proceed first. After a reboot you need to run the script again and again until it tells you that it's finished.
  The script will prompt you occationally for input preceeded by a short description that you should read. Those descriptions contain sometimes copy-pastable text required as input of installation steps.

## How it works
When placed in /root/bin the script uses functions to match the topics of the **awesome guide**.
Each time a function is finished that script will touch a FINISHED file next to itself. The last part of the filename matches the function that has finished.
When executed install_nc.sh will skip finished functions.
When it finishes the last function or skips all functions it prints "Installation and configuration of nextcloud is finished."

## Total installation time if user is present when prompted for input
The expected duration of the installation procedure is approximately 1 1/2 hours, depending on your bandwidth, since several applications will be downloaded.

## Proven to work location of the install_nc.sh script
```
/root/bin/install_nc.sh
```

## Finished files and script when installation is complete
```
FINISHED.install_nc.sh.configure_mariadb
FINISHED.install_nc.sh.configure_nextcloud
FINISHED.install_nc.sh.configure_nginx
FINISHED.install_nc.sh.configure_nginx_nextcloud
FINISHED.install_nc.sh.configure_php
FINISHED.install_nc.sh.final_configuration_nextcloud
FINISHED.install_nc.sh.install_fail2ban
FINISHED.install_nc.sh.install_letsencrypt
FINISHED.install_nc.sh.install_mariadb
FINISHED.install_nc.sh.install_nextcloud
FINISHED.install_nc.sh.install_nginx
FINISHED.install_nc.sh.install_php
FINISHED.install_nc.sh.update_vim_dkms_ssh
FINISHED.install_nc.sh.vbox_additions
install_nc.sh
```

## The output of a call when all steps are finished
```
root@...:/root/bin# /root/bin/install_nc.sh
File exists: FINISHED.install_nc.sh.update_vim_dkms_ssh. Skipping step update_vim_dkms_ssh.
File exists: FINISHED.install_nc.sh.vbox_additions. Skipping step vbox_additions.
File exists: FINISHED.install_nc.sh.install_nginx. Skipping step install_nginx.
File exists: FINISHED.install_nc.sh.install_mariadb. Skipping step install_mariadb.
File exists: FINISHED.install_nc.sh.install_php. Skipping step install_php.
File exists: FINISHED.install_nc.sh.configure_php. Skipping step configure_php.
File exists: FINISHED.install_nc.sh.configure_mariadb. Skipping step configure_mariadb.
File exists: FINISHED.install_nc.sh.configure_nginx. Skipping step configure_nginx.
File exists: FINISHED.install_nc.sh.install_letsencrypt. Skipping step install_letsencrypt.
File exists: FINISHED.install_nc.sh.configure_nginx_nextcloud. Skipping step configure_nginx_nextcloud.
File exists: FINISHED.install_nc.sh.install_nextcloud. Skipping step install_nextcloud.
File exists: FINISHED.install_nc.sh.configure_nextcloud. Skipping step configure_nextcloud.
File exists: FINISHED.install_nc.sh.final_configuration_nextcloud. Skipping step final_configuration_nextcloud.
File exists: FINISHED.install_nc.sh.install_fail2ban. Skipping step install_fail2ban.
Installation and configuration of nextcloud is finished.
```
