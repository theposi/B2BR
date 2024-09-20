# B2BR

Is a sysadmin-focused task where the goal is to set up and manage a Debian operating system within a VirtualBox virtual machine. The project encompasses a variety of administrative tasks and configurations aimed at ensuring the security, efficiency, and proper management of the system. Here’s a breakdown of the completed tasks:

### System Setup

- OS Installation: Installed Debian OS in a VirtualBox virtual machine.
- Encrypted Partitions: Configured encrypted partitions using Logical Volume - - - Manager (LVM) to ensure data security.
- SSH Service: Set up the SSH service to listen on port 4242.
- Firewall Configuration: Configured UFW firewall to allow traffic on port 4242.
### User and Group Management
- User and Group Management: Created and deleted users and groups, managed their permissions, and added users to the sudo group for administrative privileges.
### Package Management
- APT Management: Managed software packages using APT (Advanced Package Tool).
### Password Management and Policies
- Configured strict password policies to enhance system security:

Here some of the configs I used to echieve a strong password policies.

login.defs
```txt
PASS_MAX_DAYS 30
PASS_MIN_DAYS 2
PASS_WARN_AGE 7
```

Sudo config:
```txt
Defaults badpass_message = "Seems like there's a mistake, try again please"
Defaults logfile="/var/log/sudo/sudo_conf"
Defaults log_input, log_output
Defaults iolog_dir="/var/log/sudo"
Defaults passwd_tries = 3
Defaults requiretty
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
```

pam.d:
```txt
password
requisite
pam_pwquality.so
retry=3
minlen=10
ucredit=-1
dcredit=-1
lcredit=-1
maxrepeat=3
reject_username
difok=7
enforce_for_root
``` 

Finally I used `wall""` to display a monitoring script in all the term instances connected in the server:

monitoring.sh
```sh
#!/bin/bash

# OS
architecture=$(uname -a)

# Physical CPU
phcpu=$(cat /proc/cpuinfo | grep "physical id" | wc -l)

# Virtual CPU
vcpu=$(cat /proc/cpuinfo | grep processor | wc -l)

# RAM
total_ram=$(free --mega | awk '$1 == "Mem:" {printf $2}')
used_ram=$(free --mega | awk '$1 == "Mem:" {printf $3}')
percent_ram=$(free --mega | awk '$1 == "Mem:" {printf("%.2f"), $3/$2*100}')

# DISK
total_disk=$(df -m | grep "/dev/" | grep -v "/boot" | awk '{disk_t += $2} END {printf ("%.1fGb\n"), d
isk_t/1024}')
used_disk=$(df -m | grep "/dev/" | grep -v "/boot" | awk '{disk_u += $3} END {print disk_u}')
percent_disk=$(df -m | grep "/dev/" | grep -v "/boot" | awk '{disk_u += $3} {disk_t+= $2} END {printf
("%d"), disk_u/disk_t*100}')

# CPU LOAD
cpu_load=$(vmstat 1 2 | tail -1 | awk '{printf $15}')
cpu_operation=$(expr 100 - $cpu_load)
cpu_final=$(printf "%.1f" $cpu_operation)

# Last Boot
lboot=$(who -b | awk '$1 == "system" {print $4 " " $3}')

# LVM Use
lvm=$(
if lsblk | grep -q "lvm"; then
        echo "Yes"
else
        echo "No"
fi)

# TCP connections
tcpc=$(ss -ta | grep "ESTAB" | wc -l )

# Users
users=$(users | wc -w)

# IP & MAC
ip=$(hostname -I)
mac=$(ip link | grep "link/ether" | awk '{print $2}')

# SUDO Commands
sudo_cmds=$(journalctl -q _COMM=sudo | grep "COMMAND" | wc -l)

# Output
wall    "
        Architecture: $architecture
        Physical CPU: $phcpu
        Virtual CPU: $vcpu
        Memory Usage: $used_ram/${total_ram}MB ($percent_ram%)
        Disk usage: $used_disk/${total_disk} ($percent_disk%)
        CPU Load: $cpu_final
        Last boot: $lboot
        LVM: $lvm
        TCP Connections: $tcpc
        Users log: $users
        Network: $ip MAC: $mac
        Sudo commands: $sudo_cmds"
```
