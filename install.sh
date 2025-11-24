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
  pipewire pipewire-pulse pipewire-alsa wireplumber pavucontrol alsa-utils \
  nvidia nvidia-utils nvidia-settings \
  qemu-full virt-manager virt-viewer dnsmasq vde2 bridge-utils libvirt iptables-nft \
  docker docker-compose \
  wireshark-qt nmap masscan aircrack-ng hydra john hashcat whois dnsutils tcpdump gnu-netcat \
  binwalk foremost sleuthkit \
  lynis rkhunter fail2ban clamav clamtk firejail keepassxc \
  htop neovim nano filelight gparted \
  firefox \
  reflector \
  nftables

echo "[*] Generating fstab..."
genfstab -U /mnt >> /mnt/etc/fstab

echo "[*] Capturing root partition UUID for bootloader..."
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
sed -i 's/^#en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen

if ! grep -q '^en_CA.UTF-8 UTF-8' /etc/locale.gen; then
  echo 'en_CA.UTF-8 UTF-8' >> /etc/locale.gen
else
  sed -i 's/^#en_CA.UTF-8 UTF-8/en_CA.UTF-8 UTF-8/' /etc/locale.gen
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

echo "[chroot] Enabling sudo for wheel..."
sed -i 's/^# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

echo "[chroot] Making journald persistent..."
sed -i 's/^#\?Storage=.*/Storage=persistent/' /etc/systemd/journald.conf || true
systemctl restart systemd-journald || true

echo "[chroot] Writing nftables hardwall rules..."
cat > /etc/nftables.conf << 'NFT'
table inet hardwall {
  chain input {
    type filter hook input priority filter; policy drop;

    # Allow established sessions and loopback
    ct state established,related accept
    iif "lo" accept

    # Allow basic ICMP (ping, etc.)
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept

    # Explicitly slam SSH inbound
    tcp dport { 22 } drop

    # Everything else hits the log+drop chain
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

echo "[chroot] Disabling IPv6 (system-wide)..."
cat > /etc/sysctl.d/99-disable-ipv6.conf << SYSCTL
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
SYSCTL

sysctl --system || true

echo "[chroot] Creating user '$USERNAME'..."
useradd -m -G wheel,audio,video,storage,input,libvirt,docker -s /usr/bin/fish "$USERNAME"

echo
echo ">>> Set root password now:"
passwd
echo
echo ">>> Set password for $USERNAME:"
passwd "$USERNAME"

echo "[chroot] Enabling core services..."
systemctl enable NetworkManager
systemctl enable lightdm
systemctl enable libvirtd
systemctl enable docker
systemctl enable fstrim.timer
systemctl enable nftables
systemctl enable fail2ban
systemctl enable clamav-freshclam.service || true
systemctl enable clamav-daemon.service || true

echo "[chroot] Dropping MOTD with tool hints..."
cat > /etc/motd << 'MOTD'
Welcome to your hardened Arch + XFCE box.

Security & defense tools preinstalled:
  - lynis         : full system audit (sudo lynis audit system)
  - rkhunter      : rootkit checks (sudo rkhunter --check)
  - fail2ban      : ban brute-force IPs (jails configurable in /etc/fail2ban)
  - clamav/clamtk : on-demand AV scanning (freshclam auto-updates DB)
  - firejail      : sandbox apps (e.g. firejail firefox)
  - nftables      : hardwall ruleset (see /etc/nftables.conf)
  - keepassxc     : password manager (stores secrets locally, no cloud)

Offense / recon / forensics:
  - wireshark-qt  : packet analysis
  - nmap, masscan : network scanning (stealth vs internet-scale)
  - aircrack-ng   : Wi-Fi stuff when needed
  - hydra, john, hashcat : auth cracking / auditing
  - binwalk       : firmware / binary inspection
  - foremost      : file carving / recovery
  - sleuthkit     : disk and filesystem forensics toolkit

Desktop toys:
  - XFCE4 + goodies (light, fast)
  - Firefox, pavucontrol, filelight, gparted, htop, neovim, nano

After first boot, run:
  sudo pacman -Syu

MOTD

echo "[chroot] Base config done."
EOF

echo
echo "=============================================="
echo " Install complete."
echo " Disk used  : $disk"
echo " Hostname   : $hostname"
echo " User       : $username"
echo " Desktop    : XFCE4"
echo " Encryption : Full LUKS on ${disk}2 -> /dev/mapper/cryptroot"
echo "=============================================="
echo "Now: reboot, unlock LUKS at prompt, and log in as '$username'."
