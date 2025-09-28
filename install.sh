apt update && apt upgrade -y && \
apt install -y ca-certificates curl gnupg lsb-release && \
mkdir -p /etc/apt/keyrings && \
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(lsb_release -cs) stable" \
  > /etc/apt/sources.list.d/docker.list && \
apt update && \
apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin && \
systemctl enable docker --now && \
/usr/sbin/usermod -aG docker $(logname) && \
chown -R root:root ./
chmod go-w ./configs/filebeat.yml
echo "Installation complete. Log out / back in (or reboot) so group changes take effect."
