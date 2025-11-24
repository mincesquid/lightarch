#!/bin/bash
set -euo pipefail

# ================== CONFIG ==================
disk="/dev/sdb"                 # THIS WILL BE WIPED COMPLETELY
hostname="thefawnz"
username="fawn"
timezone="America/Vancouver"
locale="en_US.UTF-8"
# ============================================

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this as root."
  exit 1
fi

if [ ! -b "$disk" ]; then
  echo "Disk $disk does not exist."
  exit 1
fi

echo "!!! WARNING: THIS WILL WIPE $disk COMPLETELY AND SET UP FULL LUKS ENCRYPTION !!!"
echo "Press Ctrl+C NOW to abort, or wait 10 seconds to continue..."
sleep 10

echo "[*] Cleaning previous mounts and mappings..."
umount -R /mnt 2>/dev/null || true
cryptsetup close cryptroot 2>/dev/null || true

echo "[*] Partitioning $disk (GPT: 512M EFI, rest LUKS root)..."
sgdisk -Z "$disk"
sgdisk -n1:0:+512M -t1:ef00 -c1:"EFI" "$disk"
sgdisk -n2:0:0     -t2:8300 -c2:"cryptroot" "$disk"

echo "[*] Creating filesystems..."
mkfs.fat -F32 "${disk}1"

echo "[*] Creating LUKS2 container on ${disk}2..."
cryptsetup luksFormat \
  --type luks2 \
  --cipher aes-xts-plain64 \
  --key-size 512 \
  --hash sha256 \
  "${disk}2"

echo "[*] Opening LUKS container..."
cryptsetup open "${disk}2" cryptroot

mkfs.ext4 -F /dev/mapper/cryptroot

echo "[*] Mounting target filesystem..."
mount /dev/mapper/cryptroot /mnt
mkdir -p /mnt/boot
mount "${disk}1" /mnt/boot

echo "[*] Pacstrap base system + XFCE + tools..."

pacstrap -K /mnt \
  base base-devel linux linux-headers linux-firmware \
  amd-ucode intel-ucode \
  cryptsetup e2fsprogs dosfstools \
  sudo git curl wget \
  networkmanager network-manager-applet \
  xfce4 xfce4-goodies \
  lightdm lightdm-gtk-greeter \
  xorg-server xorg-xinit \
  pipewire pipewire-alsa pipewire-pulse wireplumber pavucontrol alsa-utils \
  nvidia nvidia-utils nvidia-settings \
  qemu virt-manager virt-viewer dnsmasq vde2 bridge-utils libvirt iptables-nft \
  docker docker-compose \
  wireshark-qt nmap masscan aircrack-ng hydra john hashcat \
  whois bind tcpdump openbsd-netcat \
  binwalk foremost sleuthkit testdisk ddrescue \
  lynis rkhunter fail2ban clamav clamtk firejail \
  keepassxc \
  htop btop tree rsync zip unzip p7zip lsof strace \
  gparted filelight flameshot \
  firefox \
  reflector \
  nftables \
  zram-generator \
  fish

echo "[*] Generating fstab..."
genfstab -U /mnt >> /mnt/etc/fstab

echo "[*] Capturing root partition UUID..."
root_uuid=$(blkid -s UUID -o value "${disk}2")

echo "[*] Entering chroot to configure system..."
arch-chroot /mnt env \
  HOSTNAME="$hostname" \
  USERNAME="$username" \
  TIMEZONE="$timezone" \
  LOCALE="$locale" \
  ROOT_UUID="$root_uuid" \
  bash -e << 'EOF'
set -euo pipefail

echo "[chroot] Setting timezone and clock..."
ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
hwclock --systohc

echo "[chroot] Configuring locale..."
sed -i 's/^#en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen || true
if ! grep -q '^en_CA.UTF-8 UTF-8' /etc/locale.gen; then
  echo 'en_CA.UTF-8 UTF-8' >> /etc/locale.gen
fi

locale-gen

echo "LANG=$LOCALE" > /etc/locale.conf

echo "[chroot] Setting hostname and hosts..."
echo "$HOSTNAME" > /etc/hostname
cat > /etc/hosts << HOSTS
127.0.0.1   localhost
::1         localhost
127.0.1.1   $HOSTNAME.localdomain $HOSTNAME
HOSTS

echo "[chroot] Hardening mkinitcpio (encrypted root)..."
sed -i 's/^HOOKS=.*/HOOKS=(base udev autodetect microcode modconf kms keyboard keymap consolefont block encrypt filesystems fsck)/' /etc/mkinitcpio.conf
mkinitcpio -P

echo "[chroot] Installing systemd-boot..."
bootctl install

chmod 600 /boot/loader/random-seed 2>/dev/null || true

cat > /boot/loader/loader.conf << LOADER
default  arch
timeout  4
editor   no
LOADER

cat > /boot/loader/entries/arch.conf << BOOT
title   Arch Linux (XFCE, encrypted)
linux   /vmlinuz-linux
initrd  /amd-ucode.img
initrd  /intel-ucode.img
initrd  /initramfs-linux.img
options cryptdevice=UUID=$ROOT_UUID:cryptroot root=/dev/mapper/cryptroot rw quiet
BOOT

echo "[chroot] Enable sudo for wheel..."
sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

echo "[chroot] Make journald persistent..."
sed -i 's/^#\?Storage=.*/Storage=persistent/' /etc/systemd/journald.conf || true
systemctl restart systemd-journald || true

echo "[chroot] Writing nftables hardwall rules..."
cat > /etc/nftables.conf << 'NFT'
table inet hardwall {
  chain input {
    type filter hook input priority filter; policy drop;

    ct state established,related accept
    iif "lo" accept

    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept

    tcp dport { 22 } drop

    jump logdrop
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
    jump logdrop
  }

  chain output {
    type filter hook output priority filter; policy accept;
  }

  chain logdrop {
    log prefix "hardwall: DROP " group 1
    drop
  }
}
NFT

echo "[chroot] Disabling IPv6 system-wide..."
cat > /etc/sysctl.d/99-disable-ipv6.conf << SYSCTL
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
SYSCTL

echo "[chroot] Extra sysctl hardening..."
cat > /etc/sysctl.d/99-hardening.conf << HARD
kernel.kptr_restrict=2
kernel.unprivileged_bpf_disabled=1
kernel.randomize_va_space=2
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv6.conf.all.accept_redirects=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
HARD

sysctl --system || true

echo "[chroot] Creating user '$USERNAME'..."
useradd -m -G wheel,audio,video,storage,input,libvirt,docker -s /bin/bash "$USERNAME"
# Set shell to fish only if it exists
if [ -x /usr/bin/fish ]; then
  chsh -s /usr/bin/fish "$USERNAME"
fi

echo "[chroot] Disabling unnecessary network daemons (if present)..."
systemctl disable --now sshd.service 2>/dev/null || true
systemctl disable --now avahi-daemon.service avahi-daemon.socket 2>/dev/null || true

echo "[chroot] Enabling core services..."
systemctl enable NetworkManager
systemctl enable lightdm
systemctl enable libvirtd
systemctl enable docker
systemctl enable fstrim.timer
systemctl enable nftables
systemctl enable fail2ban
systemctl enable clamav-freshclam.service 2>/dev/null || true
systemctl enable clamav-daemon.service 2>/dev/null || true

echo "[chroot] Drop MOTD with tool hints..."
cat > /etc/motd << 'MOTD'
Welcome to your hardened Arch + XFCE system, fawn.

Security / defense:
  - lynis          : sudo lynis audit system
  - rkhunter       : sudo rkhunter --check
  - fail2ban       : bans brute-force IPs (config in /etc/fail2ban)
  - clamav/clamtk  : on-demand AV scanning
  - firejail       : sandbox apps (e.g. firejail firefox)
  - nftables       : hardwall ruleset (/etc/nftables.conf)
  - keepassxc      : password manager (local, no cloud)

Recon / offense / forensics:
  - wireshark-qt   : packet analysis (run as non-root, use group perms)
  - nmap, masscan  : network scanning
  - aircrack-ng    : Wi-Fi tools
  - hydra, john, hashcat : password/auth auditing
  - binwalk        : firmware / binary inspection
  - foremost       : file carving / recovery
  - sleuthkit      : filesystem forensics
  - testdisk/ddrescue: recovery / imaging
  - tcpdump, whois, dig (from bind), nc (openbsd-netcat)

Desktop / quality of life:
  - XFCE4 + goodies
  - Firefox, pavucontrol, filelight, gparted
  - htop, btop, neovim, nano, fish shell

After first boot:
  sudo pacman -Syu
echo ">>> Set ROOT password now:"
max_retries=5
retry_count=0
until passwd; do
  retry_count=$((retry_count+1))
  echo "Password setup failed, try again..."
  if [ "$retry_count" -ge "$max_retries" ]; then
    read -p "Maximum attempts reached. [S]kip, [E]xit, or [C]ontinue? " choice
    case "$choice" in
      [Ss]*) echo "Skipping root password setup."; break ;;
      [Ee]*) echo "Exiting script."; exit 1 ;;
      *) retry_count=0 ;;
    esac
  fi
done

echo
echo ">>> Set password for $USERNAME:"
retry_count=0
until passwd "$USERNAME"; do
  retry_count=$((retry_count+1))
  echo "Password setup for $USERNAME failed, try again..."
  if [ "$retry_count" -ge "$max_retries" ]; then
    read -p "Maximum attempts reached. [S]kip, [E]xit, or [C]ontinue? " choice
    case "$choice" in
      [Ss]*) echo "Skipping password setup for $USERNAME."; break ;;
      [Ee]*) echo "Exiting script."; exit 1 ;;
      *) retry_count=0 ;;
    esac
  fi
  fi
done

echo
echo ">>> Set password for $USERNAME:"
max_retries=5
attempt=1
until passwd "$USERNAME"; do
  echo "Password setup for $USERNAME failed, try again... ($attempt/$max_retries)"
  attempt=$((attempt+1))
  if [ "$attempt" -gt "$max_retries" ]; then
    echo "Maximum password attempts reached for $USERNAME. Aborting."
    exit 1
  fi
echo
echo ">>> Set password for $USERNAME:"
until passwd "$USERNAME"; do
  echo "Password setup for $USERNAME failed, try again..."
done

echo "[chroot] Base config done."
EOF

echo
echo "=============================================="
echo "  INSTALL COMPLETE"
echo "  Disk used   : $disk"
echo "  Hostname    : $hostname"
echo "  User        : $username"
echo "  Desktop     : XFCE4"
echo "  Encryption  : Full LUKS2 on ${disk}2 -> /dev/mapper/cryptroot"
echo "=============================================="
echo "Now: reboot, unlock LUKS at prompt, log in as '$username'."
