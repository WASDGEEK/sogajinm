# node address (forward poert 44443 only change in shell
1.1.1.1;10010;0;ws;tls;path=/bbbb/|host=fuck.you|outside_port=888
# shell
mkdir soga-jin && cd soga-jin && curl https://raw.githubusercontent.com/WASDGEEK/sogajinm/main/install.sh -o install.sh && chmod +x install.sh && bash install.sh
# firewall 
systemctl stop firewalld.service

systemctl disable firewalld.service

systemctl enable docker

service postfix stop

systemctl disable postfix
