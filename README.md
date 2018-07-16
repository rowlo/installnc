# installnc
A script that automates installation of nextcloud on (k)ubuntu 18.04 LTS running in a VirtualBox guest.

It's a bash script for installing a nextcloud server in a VirtualBox guest with letsencrypt SSL and nginx as subdir in dyndns domain and nextcloud_data dir linked to a shared folder.
The script follows the description provided with that **awesome guide** [German]:
[Nextcloud auf Ubuntu Server mit nginx, MariaDB, PHP, Let’s Encrypt, Redis und Fail2ban](https://decatec.de/home-server/nextcloud-auf-ubuntu-server-mit-nginx-mariadb-php-lets-encrypt-redis-und-fail2ban/ "Nextcloud auf Ubuntu Server mit nginx, MariaDB, PHP, Let’s Encrypt, Redis und Fail2ban")

Additionally it also utilizes
* [Unix & Linux Stack Exchange answer on Systemd mount fails. Where= setting doesn't match unit name](https://unix.stackexchange.com/a/345518 "Unix & Linux Stack Exchange answer on Systemd mount fails. Where= setting doesn't match unit name")
* [Unix & Linux Stack Exchange: How to mount shared folder from VirtualBox at boot time in Debian](https://unix.stackexchange.com/questions/335609/how-to-mount-shared-folder-from-virtualbox-at-boot-time-in-debian "Unix & Linux Stack Exchange: How to mount shared folder from VirtualBox at boot time in Debian")
* [systemd.mount — Mount unit configuration](https://www.freedesktop.org/software/systemd/man/systemd.mount.html "systemd.mount — Mount unit configuration")


## Original author of install_nc.sh script
[Robert Wloch](https://github.com/rowlo "Robert Wloch on github")

## IMPORTANT NOTE
If you've used that script to build your own nextcloud server for (k)ubuntu 16.04 LTS in the past: There was an error in the systemd mount script. The error silently skipped mounting the shared folder for the cloud data. The effect is that all the data was stored in the VM and could potentially fill the VM disk to its limit.

### How to check if you're affected
Run that command inside your VM (exchange "media-sfclouddata.mount" by whatever you set in install_nc.sh at variable MOUNTPOINTVBOXFS):
```
cat /etc/systemd/system/media-sfclouddata.mount | grep gui=
```
If it prints you a line starting with "Options=umask=0007" then you need to fix that data problem because you're in BIG TROUBLE: Your nextcloud VM can become permanently unusable when the VM disk becomes full!

### How to fix it
1. Make sure your nextcloud VM is running
2. In you router: Deaktivate the port forwarding while fixing the data issue
3. Go to your host OS where the VM runs.
4. Open a file browser and enter as URL (change user name and VM hostname to match your system: "fish://vmcloud@vmcloud/media/sfclouddata/".
5. Copy all the files in that folder to where the shared folder actually is on your host OS. If unsure, look it up in the appliance configuration in VirtualBox.
6. SSH into the nextcloud VM
7. Edit systemd mount file and replace "gui=" with "gid=" in that "Options"-line:
   ```
   sudo vim /etc/systemd/system/media-sfclouddata.mount
   ```
8. In your VM run that command to move your data to another folder as backup:
   ```
   sudo mv /media/sfclouddata /media/sfclouddata.vm && sudo mkdir /media/sfclouddata
   ```
9. Reboot your nextcloud vm
10. In your VM check if that systemd mount is active and without errors with:
    ```
    systemctl status media-sfclouddata.mount
    ```
11. Reactivate your port forwarding in you router.
12. Login to you nextcloud web interface and check that your data is there.
13. Remove the backup datafolder in your VM (see step 8.)
14. Sorry and appologies for the inconvenience!

## Usage:
1. Modify the top three variables of the install_nc.sh script to match your needs:
   - VIRTUALBOX_SHARED_FOLDER_NAME_NEXTCLOUD_DATA="cloud-data"
   - MOUNTPOINTVBOXFS="/media/sfclouddata"
   - SERVER_DOMAIN_NAME="your-dyndns-domain.com"
2. Prepare a shared folder for your cloud data. If you like, put it in an encrypted container and mount it, e.g. "/media/truecrypt2/cloud-data/nextcloud_data/"
  In the example truecrypt2 is an ext4 file container, "cloud-data" is the shared folder , and "nextcloud_data" is the nextcloud data folder with changable permissions from within the guest.
3. In VirtualBox create a guest from a kubuntu 18.04 LTS iso and configure the shared folder. Stick to "cloud_data" if you like.
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
