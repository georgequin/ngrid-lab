#!/bin/bash
# Host bootstrap: ${role} host, team ${team}. Runs once at first boot.
set -x
exec > /var/log/lab-bootstrap.log 2>&1
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y docker.io docker-compose-v2 xrdp xfce4 xfce4-terminal unzip curl python3 openssl
systemctl enable --now docker xrdp

# AWS CLI v2 (to pull the bundle from S3 using the instance role)
curl -sL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscli.zip && unzip -q /tmp/awscli.zip -d /tmp && /tmp/aws/install

mkdir -p /opt/lab && cd /opt/lab
aws s3 cp s3://${bucket}/${role}/${role}.tar.gz /tmp/bundle.tgz --region $(curl -s -H "X-aws-ec2-metadata-token: $(curl -s -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)" http://169.254.169.254/latest/meta-data/placement/region)
tar xzf /tmp/bundle.tgz -C /opt/lab
docker build -t ussd-range:latest /opt/lab/range

cat > /opt/lab/.env <<ENV
ADMIN_TOKEN=${admin_token}
PARTICIPANTS=${participants}
ENV
chmod 600 /opt/lab/.env
for i in $(seq 1 ${participants}); do mkdir -p /opt/lab/data/p$i; done
python3 /opt/lab/scripts/gen_compose.py ${team} ${participants} '${lab_secret}' '${admin_token}' > /opt/lab/docker-compose.yml
chmod 700 /opt/lab/data /opt/lab/scripts 2>/dev/null; chmod 600 /opt/lab/docker-compose.yml
docker compose -f /opt/lab/docker-compose.yml up -d

# Participant desktop accounts (NOT in the docker group, no sudo): p1..pN, password shared per team
echo xfce4-session > /etc/skel/.xsession
for i in $(seq 1 ${participants}); do
  useradd -m -s /bin/bash p$i && echo "p$i:${team_pw}" | chpasswd
  mkdir -p /home/p$i/Desktop
  cp /opt/lab/docs/STUDENT_HANDOUT.md /home/p$i/Desktop/ 2>/dev/null
  echo "Your range: http://127.0.0.1:$((8000+i))   (open it through Burp's browser)" > /home/p$i/Desktop/MY_RANGE.txt
  chown -R p$i:p$i /home/p$i
done
chmod 700 /opt/lab   # participants cannot read range source, compose file, secrets or answer keys
%{ if role == "student" ~}
chmod 700 /opt/lab/scripts
%{ endif ~}

# Burp Suite Community (free: Proxy/Repeater OK, Intruder is rate-limited, which fits the brute-force guardrail)
curl -sL "${burp_url}" -o /tmp/burp.sh && sh /tmp/burp.sh -q -dir /opt/burp || echo "BURP INSTALL FAILED: install manually"
for i in $(seq 1 ${participants}); do
  printf '[Desktop Entry]\nType=Application\nName=Burp Suite\nExec=/opt/burp/BurpSuiteCommunity\nTerminal=false\n' > /home/p$i/Desktop/Burp.desktop
  chmod +x /home/p$i/Desktop/Burp.desktop; chown p$i:p$i /home/p$i/Desktop/Burp.desktop
done

# Cost safety net: stop the instance N minutes after every boot
echo "@reboot root /sbin/shutdown -h +${shutdown_min}" > /etc/cron.d/autostop
/sbin/shutdown -h +${shutdown_min}
echo BOOTSTRAP-COMPLETE
