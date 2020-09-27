# Residual Trust: Expired Domains

## Directory Structure
* `/ansible/`
  * move `ansible.cfg, ssh.cfg, hosts` into your Ansible directory (`/etc/ansible` in Linux)
  * setup your SSH configs to use the correct keys
  * test your connection with `ansible all -m ping`
* `/extract/` - scripts for managing data ingestion
  * `transfer_containers.py` - rsync'ing data to shippers
  * `unzip.py` - gradually decompressing `.tar.gz` log files for Filebeat