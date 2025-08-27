# Controlador de Domínio Primário, Secundário e Servidor de Arquivos

# Debian Linux 13 - SAMBA4 compilado

#### Layout de rede usado no laboratório:

```bash
firewall        192.168.70.254 (enp1s0) - 192.168.0.254 (enp7s0) (ssh 22254)
pdc01           192.168.70.253   (ssh 22253)
pdc02           192.168.70.252   (ssh 22252)
intranet        192.168.70.251   (ssh 22251)
arquivos        192.168.70.250   (ssh 22250)

; firewall      Servidor Firewall OPNSense
; pdc01         Controlador de Domínio primário
; pdc02         Controlador de Domínio secundário
; intranet      Servidor de Intranet
; arquivos      Servidor de Arquivos
```

#### Instalando as dependências para compilação do código fonte  do Samba4:

```bash
export DEBIAN_FRONTEND=noninteractive;apt-get update; apt-get install vim net-tools rsync acl apt-utils attr autoconf bind9-utils binutils bison build-essential rsync ccache chrpath curl debhelper bind9-dnsutils docbook-xml docbook-xsl flex gcc gdb git glusterfs-common gzip heimdal-multidev hostname htop krb5-config krb5-user lcov libacl1-dev libarchive-dev libattr1-dev libavahi-common-dev libblkid-dev libbsd-dev libcap-dev libcephfs-dev libcups2-dev libdbus-1-dev libglib2.0-dev libgnutls28-dev libgpgme-dev libicu-dev libjansson-dev libjs-jquery libjson-perl libkrb5-dev libldap2-dev liblmdb-dev libncurses-dev libpam0g-dev libparse-yapp-perl libpcap-dev libpopt-dev libreadline-dev libsystemd-dev libtasn1-bin libtasn1-6-dev libunwind-dev lmdb-utils locales lsb-release make mawk mingw-w64 patch perl perl-modules-5.40 pkg-config procps psmisc python3 python3-cryptography python3-dbg python3-dev python3-dnspython python3-gpg python3-iso8601 python3-markdown python3-matplotlib python3-pexpect python3-pyasn1 rsync sed tar tree uuid-dev wget xfslibs-dev xsltproc zlib1g-dev -y
```

#### Setando e validando o hostname do pdc01:

```bash
hostnamectl set-hostname pdc01
```

#### Configurando o arquivo de hosts:

```bash
vim /etc/hosts
```

```bash
.0.0.1             localhost
127.0.1.1          pdc01.officinas.edu    pdc01
192.168.70.253     pdc01.officinas.edu    pdc01
```

```bash
hostname -f
```

#### Setando ip fixo no servidor pdc01:

```bash
vim /etc/network/interfaces
```

```bash
iface enp1s0 inet static
address           192.168.70.253
netmask           255.255.255.0
gateway           192.168.70.254
```

#### Setando endereço do firewall como resolvedor externo (temporário até provisionar o domínio):

```bash
vim /etc/resolv.conf
```

```bash
domain             officinas.edu
search             officinas.edu.
nameserver         192.168.70.254
```

#### Validando o ip da placa:

```bash
ip -c addr
```

```bash
ip -br link
```

#### Baixando e compilando o código fonte do Samba4:

```bash
wget https://download.samba.org/pub/samba/samba-4.22.3.tar.gz
```

```bash
tar -xvzf samba-4.22.3.tar.gz
```

```bash
cd samba-4.22.3
```

```bash
./configure --prefix=/opt/samba \
  --with-winbind \
  --with-shared-modules=idmap_rid,idmap_ad \
```

```bash
make -j$(nproc)
```

```bash
make install
```

```bash
make clean
```

#### Validar se o winbind e NSS foram compilados

```bash
/opt/samba/sbin/smbd -b | grep WINBIND
```

```bash
WITH_WINBIND
```

```bash
/opt/samba/sbin/smbd -b | grep LIBDIR
```

```bash
LIBDIR: /opt/samba/lib
```

```bash
find /opt/samba -name "libnss_winbind.so*"
```

```bash
/opt/samba/lib/libnss_winbind.so.2
```

## Linkar as bibliotecas compiladas do Winbind e NSS ao path do Sistema Operacional (rode esses comandos manualmente sem copiar e colar):

```bash
ln -s /opt/samba/lib/libnss_winbind.so.2 /lib/x86_64-linux-gnu
```

```bash
ln -s /lib/x86_64-linux-gnu/libnss_winbind.so.2 /lib/x86_64-linux-gnu/libnss_winbind.so
```

```bash
ldconfig
```

#### Adicionando /opt/Samba ao path padrão do Linux, colando a linha completa ao final do .bashrc:

#### PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/samba/bin:/opt/samba/sbin"

```bash
vim ~/.bashrc
```

```bash
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/samba/bin:/opt/samba/sbin"
```

#### Relendo o arquivo de profile:

```bash
source ~/.bashrc
```

#### Criando o daemon de inicialização do Samba4 com o sistema:

```bash
vim /etc/systemd/system/samba-ad-dc.service
```

```bash
[Unit]
Description=Samba 4 Active Directory Domain Controller
After=network.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/samba/sbin/samba --foreground --no-process-group
Restart=always
LimitNOFILE=16384

[Install]
WantedBy=multi-user.target
```

```bash
chmod +x /etc/systemd/system/samba-ad-dc.service
```

#### Editando o nssswitch:

```bash
vim /etc/nsswitch.conf
```

```bash
# /etc/nsswitch.conf
#
# Example configuration of GNU Name Service Switch functionality.
# If you have the `glibc-doc-reference' and `info' packages installed, try:
# `info libc "Name Service Switch"' for information about this file.

passwd:         files systemd winbind
group:          files systemd winbind
shadow:         files systemd
gshadow:        files systemd

hosts:          files dns
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis
```

#### Provisionando o novo domínio suportado pelo pdc01:

```bash
samba-tool domain provision --use-rfc2307 --interactive --option=”interfaces=lo ens18” --option=”bind interfaces only=yes”
```

#### Habilitando o daemon pra subir no boot do sistema:

```bash
systemctl daemon-reload
```

```bash
systemctl enable samba-ad-dc.service
```

```bash
systemctl start samba-ad-dc.service
```

```bash
systemctl status samba-ad-dc.service
```

#### Linkando o arquivo krb5.conf do Samba4 ao /etc do sistema:

```bash
mv /etc/krb5.conf{,.orig}
```

```bash
ln -sf /opt/samba/private/krb5.conf /etc/krb5.conf
```

#### APÓS o provisionamento da Samba4, precisamos reconfigurar o /etc/resolv.conf e setar o DNS apontando a resolução de nomes para o próprio pdc01:

```bash
vim /etc/resolv.conf
```

```bash
domain           officinas.edu
search           officinas.edu.
nameserver       127.0.0.1
```

#### Bloqueando alteração do resolv.conf:

```bash
chattr +i /etc/resolv.conf
```

#### Validando resolvedor de nomes pelo pdc01:

```bash
nslookup pdc01.officinas.edu
```

### Vai validar na tela:

```bash
Server:         127.0.0.1
Address:        127.0.0.1#53

Name:   pdc01.officinas.edu
Address: 192.168.70.253
```

#### Reboot do servidor pdc01:

```bash
reboot
```

#### Validando os serviços do Samba4 no boot do sistema:

```bash
ps aux | grep samba
```

```bash
ps aux | egrep "samba|smbd|nmbd|winbind"
```

```bash
find / -name samba.pid
```

```bash
pgrep samba
```

#### Dando poderes de root ao Administrator:

```bash
vim /opt/samba/etc/user.map
```

```bash
!root=officinas.edu\Administrator
```

#### Editando o arquivo smb.conf e adicionando no dns forwarder, quem resolve nomes para consultas externas (o Firewall):

```bash
cp /opt/samba/etc/smb.conf{,.orig}
```

```bash
vim /opt/samba/etc/smb.conf
```

```bash
[global]
      bind interfaces only = Yes
      dns forwarder = 192.168.70.254
      interfaces = lo ens18
      netbios name = pdc01
      realm = OFFICINAS.EDU
      server role = active directory domain controller
      workgroup = OFFICINAS
      idmap_ldb:use rfc2307 = yes

[sysvol]
      path = /opt/samba/var/locks/sysvol
      read only = No

[netlogon]
      path = /opt/samba/var/locks/sysvol/officinas.edu/scripts
      read only = No
```

#### Relendo a configuração do Samba4:

```bash
smbcontrol all reload-config
```

#### Validando usuários da base do ldap local:

```bash
cat /etc/passwd | grep root
```

#### Validando usuários de rede do Samba4 (Intermediados pelo winbind):

```bash
samba-tool user show administrator
```

```bash
getent passwd administrator
```

```bash
wbinfo -u
```

```bash
wbinfo -g
```

```bash
wbinfo --ping-dc
```

```bash
getent group "Domain Admins"
```

#### Validando daemons ativos:

```bash
ps aux | egrep "samba|smbd|nmbd|winbind"
```

```bash
ps axf
```

#### Consultando serviços do SAMBA4:

```bash
smbclient --version
```

```bash
smbclient -L pdc01 -U Administrator
```

```
Password for [OFFICINAS\Administrator]:

    Sharename       Type      Comment
    ---------       ----      -------
    sysvol          Disk      
    netlogon        Disk      
    IPC$            IPC       IPC Service (Samba 4.22.3)
SMB1 disabled -- no workgroup available
```

```bash
smbclient //localhost/netlogon -UAdministrator -c "ls"
```

```
Password for [OFFICINAS\Administrator]:
  .                                   D        0  Tue Jul 15 22:23:29 2025
  ..                                  D        0  Tue Jul 15 22:23:29 2025

        19353424 blocks of size 1024. 12404868 blocks available
```

```bash
testparm
```

```bash
Load smb config files from /opt/samba/etc/smb.conf
Loaded services file OK.
Weak crypto is allowed by GnuTLS (e.g. NTLM as a compatibility fallback)

Server role: ROLE_ACTIVE_DIRECTORY_DC

Press enter to see a dump of your service definitions

# Global parameters
[global]
    bind interfaces only = Yes
    dns forwarder = 192.168.70.253 192.168.70.254
    interfaces = lo ens18
    passdb backend = samba_dsdb
    realm = OFFICINAS.EDU
    server role = active directory domain controller
    workgroup = OFFICINAS
    rpc_server:tcpip = no
    rpc_daemon:spoolssd = embedded
    rpc_server:spoolss = embedded
    rpc_server:winreg = embedded
    rpc_server:ntsvcs = embedded
    rpc_server:eventlog = embedded
    rpc_server:srvsvc = embedded
    rpc_server:svcctl = embedded
    rpc_server:default = external
    winbindd:use external pipes = true
    idmap_ldb:use-rfc2307 = yes
    idmap config * : backend = tdb
    map archive = No
    vfs objects = dfs_samba4 acl_xattr


[sysvol]
    path = /opt/samba/var/locks/sysvol
    read only = No


[netlogon]
    path = /opt/samba/var/locks/sysvol/officinas.edu/scripts
    read only = No
```

```bash
samba-tool domain level show
```

#### Desabilitando complexidade de senhas (inseguro):

```bash
samba-tool domain passwordsettings show
```

```bash
samba-tool domain passwordsettings set --complexity=off
```

```bash
samba-tool domain passwordsettings set --history-length=0
```

```bash
samba-tool domain passwordsettings set --min-pwd-length=0
```

```bash
samba-tool domain passwordsettings set --min-pwd-age=0
```

```bash
samba-tool user setexpiry Administrator --noexpiry
```

#### Relendo as configurações do SAMBA4:

```bash
smbcontrol all reload-config
```

#### Validando a troca de tickets do Kerberos:

```bash
 kinit Administrator@OFFICINAS.EDU
```

```bash
klist 
```

```
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: Administrator@OFFICINAS.EDU

Valid starting       Expires              Service principal
15/07/2025 22:35:50  16/07/2025 08:35:50  krbtgt/OFFICINAS.EDU@OFFICINAS.EDU
    renew until 16/07/2025 22:35:46
```

#### Consultando as bases do kerberos, ldap e dns:

```bash
host -t srv _kerberos._tcp.officinas.edu
```

```
_kerberos._tcp.officinas.edu has SRV record 0 100 88 pdc01.officinas.edu.
```

```bash
host -t srv _ldap._tcp.officinas.edu
```

```
_ldap._tcp.officinas.edu has SRV record 0 100 389 pdc01.officinas.edu.
```

```bash
host -t A pdc01.officinas.edu.
```

```
pdc01.officinas.edu has address 192.168.70.253
```

```bash
dig officinas.edu
```

```
; <<>> DiG 9.20.9-1-Debian <<>> officinas.edu
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39283
;; flags: qr aa rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0

;; QUESTION SECTION:
;officinas.edu.            IN    A

;; ANSWER SECTION:
officinas.edu.        900    IN    A    192.168.70.253

;; AUTHORITY SECTION:
officinas.edu.        3600    IN    SOA    pdc01.officinas.edu. hostmaster.officinas.edu. 19 900 600 86400 3600

;; Query time: 0 msec
;; SERVER: 192.168.70.253#53(192.168.70.253) (UDP)
;; WHEN: Tue Jul 15 22:36:46 -03 2025
;; MSG SIZE  rcvd: 100
```

THAT’S ALL FOLKS!!

# Controlador de Domínio secundário com Samba4 no Debian 12

#### Layout de rede usado no laboratório:

```bash
firewall        192.168.70.254 (enp1s0) - 192.168.0.254 (enp7s0) (ssh 22254)
pdc01           192.168.70.253   (ssh 22253)
pdc02           192.168.70.252   (ssh 22252)
intranet        192.168.70.251   (ssh 22251)
arquivos        192.168.70.250   (ssh 22250)

; firewall      Servidor Firewall OPNSense
; pdc01         Controlador de Domínio primário
; pdc02         Controlador de Domínio secundário
; intranet      Servidor de Intranet
; arquivos      Servidor de Arquivos
```

#### Instalando as dependências para compilação do código fonte  do Samba4:

```bash
export DEBIAN_FRONTEND=noninteractive;apt-get update; apt-get install vim net-tools rsync acl apt-utils attr autoconf bind9-utils binutils bison build-essential rsync ccache chrpath curl debhelper bind9-dnsutils docbook-xml docbook-xsl flex gcc gdb git glusterfs-common gzip heimdal-multidev hostname htop krb5-config krb5-user lcov libacl1-dev libarchive-dev libattr1-dev libavahi-common-dev libblkid-dev libbsd-dev libcap-dev libcephfs-dev libcups2-dev libdbus-1-dev libglib2.0-dev libgnutls28-dev libgpgme-dev libicu-dev libjansson-dev libjs-jquery libjson-perl libkrb5-dev libldap2-dev liblmdb-dev libncurses-dev libpam0g-dev libparse-yapp-perl libpcap-dev libpopt-dev libreadline-dev libsystemd-dev libtasn1-bin libtasn1-6-dev libunwind-dev lmdb-utils locales lsb-release make mawk mingw-w64 patch perl perl-modules-5.40 pkg-config procps psmisc python3 python3-cryptography python3-dbg python3-dev python3-dnspython python3-gpg python3-iso8601 python3-markdown python3-matplotlib python3-pexpect python3-pyasn1 rsync sed tar tree uuid-dev wget xfslibs-dev xsltproc zlib1g-dev -y
#### Setando e validando o hostname do pdc02:

```bash
vim /etc/hostname
```

```bash
pdc02
```

```bash
hostname -f
```

```bash
pdc02.officinas.edu
```

#### Configurando o arquivo de hosts:

```bash
vim /etc/hosts
```

```bash
.0.0.1              localhost
127.0.1.1           pdc02.officinas.edu       pdc02
192.168.70.252      pdc02.officinas.edu       pdc02
192.168.70.253      pdc01.officinas.edu       pdc01
```

#### Setando ip fixo no servidor pdc02:

```bash
vim /etc/network/interfaces
```

```bash
allow-hotplug enp1s0
iface enp1s0 inet static
address           192.168.70.252
netmask           255.255.255.0
gateway           192.168.70.254
dns-nameservers   192.168.70.253
dns-search        officinas.edu
```

#### Apontando o endereço do resolvedor de nomes principal da rede pro Controlador de domínio primário, pdc01 (temporário, até provisionar):

```bash
vim /etc/resolv.conf
```

```bash
domain           officinas.edu
search           officinas.edu.
nameserver       192.168.70.253
nameserver       127.0.0.1
```

#### Validando a resolução de nomes pelo pdc01:

```bash
nslookup officinas.edu
```

```bash
Server:         192.168.70.253
Address:        192.168.70.253#53

Name:   officinas.edu
Address: 192.168.70.253
Name:   officinas.edu
Address: 192.168.70.252
```

#### Relendo as configurações de rede:

```bash
systemctl restart networking
```

#### Validando o ip da placa:

```bash
ip -c addr
```

```bash
ip -br link
```

#### Baixando e compilando o código fonte do Samba4:

```bash
wget https://download.samba.org/pub/samba/samba-4.22.3.tar.gz
```

```bash
tar -xvzf samba-4.22.3.tar.gz
```

```bash
cd samba-4.22.3
```

```bash
./configure --prefix=/opt/samba
```

```bash
make && make install
```

#### Adicionando /opt/Samba ao path padrão do Linux, colando a linha completa ao final do .bashrc:

#### PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/samba/bin:/opt/samba/sbin"

```bash
vim ~/.bashrc
```

```bash
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/samba/bin:/opt/samba/sbin"
```

#### Relendo o arquivo de profile:

```bash
source ~/.bashrc
```

#### Criando o daemon de inicialização do Samba4 com o sistema:

```bash
vim /etc/systemd/system/samba-ad-dc.service
```

```bash
[Unit]
   Description=Samba4 Active Directory Slave Domain Controller
   After=network.target remote-fs.target nss-lookup.target

[Service]
   Type=forking
   ExecStart=/opt/samba/sbin/samba -D
   PIDFile=/opt/samba/var/run/samba.pid

[Install]
   WantedBy=multi-user.target
```

```bash
chmod +x /etc/systemd/system/samba-ad-dc.service
```

#### Editando o nssswitch:

```bash
vim /etc/nsswitch.conf
```

```bash
# /etc/nsswitch.conf
#
# Example configuration of GNU Name Service Switch functionality.
# If you have the `glibc-doc-reference' and `info' packages installed, try:
# `info libc "Name Service Switch"' for information about this file.

passwd:         files systemd winbind
group:          files systemd winbind
shadow:         files systemd
gshadow:        files systemd

hosts:          files dns
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis
```

#### Habilitando o daemon pra subir no boot do sistema:

```bash
systemctl daemon reload
```

```bash
systemctl enable samba-ad-dc.service
```

```bash
systemctl start samba-ad-dc.service
```

```bash
systemctl status samba-ad-dc.service
```

#### Editando o arquivo do kerberos:

```bash
mv /etc/krb5.conf{,.orig}
```

```bash
vim /etc/krb5.conf
```

```bash
[libdefaults]
    dns_lookup_realm = false
    dns_lookup_kdc = true
    default_realm = OFFICINAS.EDU
```

#### Provisionando o servidor pdc02:

```bash
samba-tool domain join OFFICINAS.EDU DC -U Administrator --realm=OFFICINAS.EDU --dns-backend=SAMBA_INTERNAL --option="interfaces=lo enp1s0" --option="bind interfaces only=yes" --option="idmap_ldb:use-rfc2307=yes"
```

#### Editando o arquivo smb.conf:

```bash
vim /opt/samba/etc/smb.conf
```

```bash
# Global parameters
[global]
    bind interfaces only = Yes
    dns forwarder = 192.168.70.253 192.168.70.254
    interfaces = lo enp1s0
    netbios name = pdc02
    realm = OFFICINAS.EDU
    server role = active directory domain controller
    workgroup = OFFICINAS
    idmap_ldb:use-rfc2307 = yes

[sysvol]
    path = /opt/samba/var/locks/sysvol
    read only = No

[netlogon]
    path = /opt/samba/var/locks/sysvol/officinas.edu/scripts
    read only = No
```

#### Validando as entradas DNS usadas:

```bash
apt install ldb-tools
```

```bash
host -t A officinas.edu.
```

#### (SE NECESSÁRIO), SE Necessário, adicione as entradas do pdc02, manualmente AO DNS do Samba4, no pdc01:

```bash
samba-tool dns add pdc01 OFFICINAS.EDU pdc02 A 192.168.70.252 -U administrator
```

```bash
ldbsearch -H /opt/samba/private/sam.ldb '(invocationId=*)' --cross-ncs objectguid
```

```bash
host -t CNAME df4bdd8c-abc7-4779-b01e-4dd4553ca3e9._msdcs.officinas.edu.
```

#### SE não rodar, execute a replicação para todos os DCs:

```bash
samba-tool dns add pdc01 _msdcs.officinas.edu df4bdd8c-abc7-4779-b01e-4dd4553ca3e9 CNAME pdc02.officinas.edu -Uadministrator
```

#### PASTA SYSVOL

#### Replicando a pasta sysvol. Mapeando IDs de grupos e usuários para o pdc02 (execute estes comando NO pdc01):

```bash
tdbbackup -s .bak /opt/samba/private/idmap.ldb
```

```bash
scp -rv -p22200 /opt/samba/private/idmap.ldb.bak root@pdc02:/root
```

```bash
scp -rv -p22200 /opt/samba/var/locks/sysvol/* root@pdc02:/opt/samba/var/locks/sysvol
```

#### Aplicando o arquivo BD que enviamos do pdc01 (execute estes comandos NO pdc02):

```bash
mv /root/idmap.ldb.bak /root/idmap.ldb
```

```bash
cp -rfv /root/idmap.ldb /opt/samba/private/
```

```bash
samba-tool ntacl sysvolreset
```

#### Agora precisamos pensar que tendo dois DCs na rede, SE cair o primário o secundário assume o controle, e vice versa. Logicamente devemos apontar um pro outro como resolvedor de nomes primário, ou seja, o pdc01 vai resolver primeiro no pdc02 e o pdc02 vai resolver primeiro no pdc01:

#### Edite o /etc/resolv.conf NO pdc01 e aponte pro pdc02:

```bash
vim /etc/resolv.conf
```

```bash
domain           officinas.edu
search           officinas.edu.
nameserver       192.168.70.252 #(pdc02)
nameserver       127.0.0.1
```

#### Bloqueando a edição do arquivo resolv.conf:

```bash
chattr +i /etc/resolv.conf
```

#### E no reverso, edite o /etc/resolv.conf NO pdc02 apontando pro pdc01:

#### Desbloqueando a edição do arquivo resolv.conf:

```bash
chattr -i /etc/resolv.conf
```

```bash
vim /etc/resolv.conf
```

```bash
domain           officinas.edu
search           officinas.edu.
nameserver       192.168.70.253 #(pdc01)
nameserver       127.0.0.1
```

#### Bloqueando a edição do arquivo resolv.conf:

```bash
chattr +i /etc/resolv.conf
```

#### Validando a replicação ( execute em todos os DCs):

```bash
samba-tool drs showrepl
```

#### Criando um usuário no pdc01 (execute NO pdc01):

```bash
samba-tool user create userteste
```

```bash
samba-tool user list
```

#### Validando no pdc02, se consta o usuário criado no pdc01 (execute NO pdc02):

```bash
samba-tool user list
```

#### Validando o compartilhamento padrão:

```bash
smbclient -L localhost -U%
```

```bash
smbclient //localhost/netlogon -UAdministrator -c 'ls'
```

#### Validando o DNS local:

```bash
host -t A officinas.edu localhost
```

#### Validando a troca de tickets do kerberos:

```bash
kinit Administrator
```

```bash
klist
```

#### Validando configuração de kerberos e ldap:

```bash
host -t srv _kerberos._tcp.officinas.edu
```

```bash
host -t srv _ldap._tcp.officinas.edu
```

```bash
dig officinas.edu
```

```bash
host -t A <máquina do domínio>
```

#### Validando informações de servidor qual controla o PDC Emulator:

```bash
samba-tool fsmo show | grep -i pdc
```

```bash
samba-tool fsmo show
```

#### Validando a localização do diretório 'sysvol' do pdc01:

```bash
uname -ra
```

```bash
find /opt/samba -iname sysvol
```

```bash
     /opt/samba/var/locks/sysvol
```

#### Validando espaço disponível:

```bash
df -h
```

#### Validando a UUID do seu disco:

```bash
blkid /dev/sda2 #(Sete A SUA partição de disco)
```

#### Validando suporte ativo no Kernel ás flags de acl e segurança:

```bash
cat /boot/config-6.1.0-17-amd64 | grep _ACL
```

```bash
cat /boot/config-6.1.0-17-amd64 | grep FS_SECURITY
```

#### Gerando e enviando as chaves do ssh para sincronização entre o pdc01 e o pdc02 (crie as chaves NO pdc01 e envie a chave pública para o pdc02):

#### (Pode deixar a senha em branco SE preferir)

```bash
ssh-keygen -t rsa -b 1024
```

```bash
ssh-copy-id -p22200 -i ~/.ssh/id_rsa.pub root@pdc02 #(O MEU pdc02 usa a porta ssh 22200)
```

#### Testando a conexão por ssh sem pedir senha (SE vc deixou em branco):

```bash
ssh -p22200 pdc02
```

```bash
exit
```

#### Agora inverta a ordem e crie as chaves NO pdc02 e envie para o pdc01 (Rode estes comandos NO pdc02):

```bash
ssh-keygen -t rsa -b 1024
```

```bash
ssh-copy-id -p22250 -i ~/.ssh/id_rsa.pub root@pdc01 #(enviando para o pdc01, que usa porta ssh 22250)
```

#### Testando a conexão por ssh sem pedir senha (SE vc deixou em branco):

```bash
ssh -p22250 pdc01
```

```bash
exit
```

#### Criando script de sincronização com rsync do diretório 'sysvol' DO pdc01 para envio ao pdc02 (rode estes comando NO pdc01):

```bash
cd /opt
```

```bash
vim rsync-sysvol.sh
```

```bash
#!/bin/bash
# Sincronizando Diretorios do Sysvol do pdc01 para envio ao pdc02:
#rsync -Cravz /opt/samba/var/locks/sysvol/*  root@192.168.70.252:/opt/samba/var/locks/sysvol/
# no MEU CASO onde a porta do ssh não á a default. MEU pdc02 usa 22200:
rsync -Cravz -e "ssh -p 22200" /opt/samba/var/locks/sysvol/*  root@192.168.70.252:/opt/samba/var/locks/sysvol/
```

```bash
chmod +x rsync-sysvol
```

```bash
./rsync-sysvol
```

#### Agendando a sincronização no cron do pdc01:

```bash
crontab -e
```

```bash
*/5 * * * * root  bash /opt/rsync-sysvol.sh --silent
```

#### REPITA o processo de replicação do sysvol, agora NO pdc02, INVERTENDO os apontamentos de ip, obviamente!

#### Criando script de sincronização do diretório 'sysvol' DO pdc02 para envio ao pdc01 (rode os comando agora NO pdc02):

```bash
cd /opt
```

```bash
vim rsync-sysvol.sh
```

```bash
#!/bin/bash
# Sincronizando Diretorios do Sysvol do pdc01 para envio ao pdc02:
#rsync -Cravz /opt/samba/var/locks/sysvol/*  root@192.168.70.253:/opt/samba/var/locks/sysvol/
# no MEU CASO onde a porta do ssh não á a default. MEU pdc01 usa 22250:
rsync -Cravz -e "ssh -p 22250" /opt/samba/var/locks/sysvol/*  root@192.168.70.253:/opt/samba/var/locks/sysvol/
```

```bash
chmod +x rsync-sysvol
```

```bash
./rsync-sysvol
```

#### Agendando a sincronização no cron do pdc02:

```bash
crontab -e
```

```bash
*/5 * * * * root  bash /opt/rsync-sysvol.sh --silent
```

#### As Estações de trabalho, usarão, como DNS primário o PDC Emulator do Domínio, e como DNS secundário o PDC Secundário da rede.

#### OSYNC

#### Configurando a sincronização da pasta sysvol com osync, que vai espelhar os DCs (rode esses comandos NO pdc01, primeiro):

```bash
cd /opt
```

```bash
git clone https://github.com/deajan/osync.git
```

```bash
cd osync
```

```bash
sh ./install.sh
```

#### Vai criar o diretório /etc/osync:

#### Dentro dele vai ter o arquivo de configuração sync.conf.example. Crie um arquivo sync.conf e cole o conteúdo abaixo:

```bash
vim /etc/osync/sync.conf
```

```bash
#!/usr/bin/env bash

INSTANCE_ID="sysvol_sync"

INITIATOR_SYNC_DIR="/opt/samba/var/locks/sysvol"

TARGET_SYNC_DIR="ssh://root@192.168.70.252:22200//opt/samba/var/locks/sysvol"

SSH_RSA_PRIVATE_KEY="/root/.ssh/id_rsa"

REMOTE_3RD_PARTY_HOSTS=""

PRESERVE_ACL=yes

PRESERVE_XATTR=yes

SOFT_DELETE=yes

DESTINATION_MAILS="roor@localhost"

#REMOTE_RUN_AFTER_CMD="/opt/samba/bin/samba-tool ntacl sysvolreset"
```

#### rodando o script de atualização, que está dentro do /opt/osync, apontando pro arquivo /etc/osync/sync.conf:

```bash
./upgrade-v1.0x-v1.2x.sh /etc/osync/sync.conf
```

#### Vai ficar semelhante ao modelo abaixo:

```bash
#!/usr/bin/env bash

INSTANCE_ID="sysvol_sync"

INITIATOR_SYNC_DIR="/opt/samba/var/locks/sysvol"

TARGET_SYNC_DIR="ssh://root@192.168.70.252:22200//opt/samba/var/locks/sysvol"

SSH_RSA_PRIVATE_KEY="/root/.ssh/id_rsa"

SSH_PASSWORD_FILE=""

_REMOTE_TOKEN="SomeAlphaNumericToken9"

CREATE_DIRS=false

LOGFILE=""

MINIMUM_SPACE="10240"

BANDWIDTH="0"

SUDO_EXEC=false

RSYNC_EXECUTABLE="rsync"

RSYNC_REMOTE_PATH=""

RSYNC_PATTERN_FIRST="include"

RSYNC_INCLUDE_PATTERN=""

RSYNC_EXCLUDE_PATTERN=""

RSYNC_INCLUDE_FROM=""

RSYNC_EXCLUDE_FROM=""

PATH_SEPARATOR_CHAR=";"

SSH_COMPRESSION=true

SSH_IGNORE_KNOWN_HOSTS=false

SSH_CONTROLMASTER=false

REMOTE_HOST_PING=false
```

#### Testando o sincronizmo (ignore o erro de email):

```bash
/usr/local/bin/osync.sh /etc/osync/sync.conf --dry --verbose
```

#### Rodar o sincronizmo de fato:

```bash
/usr/local/bin/osync.sh /etc/osync/sync.conf --verbose
```

#### Agendar no cron:

```bash
crontab -e
```

```bash
*/5 * * * * root  bash /usr/local/bin/osync.sh /etc/osync/sync.conf --silent
```

#### Validando os logs em tempo real, rode o /usr/local/bin/osync.sh, mantendo outro terminal aberto com o comando:

```bash
tail -f /var/log/osync.sysvol_sync.log
```

#### INVERTENDO a sincronização com o Osync, vamos refazer tudo, incluíndo o ip e porta ssh, agora NO pdc02:

```bash
cd /opt
```

```bash
git clone https://github.com/deajan/osync.git
```

```bash
cd osync
```

```bash
sh ./install.sh
```

#### Vai criar o diretório /etc/osync:

#### Dentro dele vai ter o arquivo de configuração sync.conf.example. Crie um arquivo sync.conf e cole o conteúdo abaixo:

```bash
#!/usr/bin/env bash

INSTANCE_ID="sysvol_sync"

INITIATOR_SYNC_DIR="/opt/samba/var/locks/sysvol"

TARGET_SYNC_DIR="ssh://root@192.168.70.253:22250//opt/samba/var/locks/sysvol"

SSH_RSA_PRIVATE_KEY="/root/.ssh/id_rsa"

REMOTE_3RD_PARTY_HOSTS=""

PRESERVE_ACL=yes

PRESERVE_XATTR=yes

SOFT_DELETE=yes

DESTINATION_MAILS="roor@localhost"

#REMOTE_RUN_AFTER_CMD="/opt/samba/bin/samba-tool ntacl sysvolreset"
```

#### Vai precisa configurar seu ip e o path pra rodar o script de atualização, apontando pro arquivo sync.conf:

```bash
./upgrade-v1.0x-v1.2x.sh /etc/osync/sync.conf
```

#### Vai ficar semelhante ao modelo abaixo:

```bash
#!/usr/bin/env bash

INSTANCE_ID="sysvol_sync"

INITIATOR_SYNC_DIR="/opt/samba/var/locks/sysvol"

TARGET_SYNC_DIR="ssh://root@192.168.70.253:22250//opt/samba/var/locks/sysvol"

SSH_RSA_PRIVATE_KEY="/root/.ssh/id_rsa"

SSH_PASSWORD_FILE=""

_REMOTE_TOKEN="SomeAlphaNumericToken9"

CREATE_DIRS=false

LOGFILE=""

MINIMUM_SPACE="10240"

BANDWIDTH="0"

SUDO_EXEC=false

RSYNC_EXECUTABLE="rsync"

RSYNC_REMOTE_PATH=""

RSYNC_PATTERN_FIRST="include"

RSYNC_INCLUDE_PATTERN=""

RSYNC_EXCLUDE_PATTERN=""

RSYNC_INCLUDE_FROM=""

RSYNC_EXCLUDE_FROM=""

PATH_SEPARATOR_CHAR=";"

SSH_COMPRESSION=true

SSH_IGNORE_KNOWN_HOSTS=false

SSH_CONTROLMASTER=false

REMOTE_HOST_PING=false
```

#### Testar o sincronizmo (ignore o erro de email):

```bash
/usr/local/bin/osync.sh /etc/osync/sync.conf --dry --verbose
```

#### Rodar o sincronizmo de fato:

```bash
/usr/local/bin/osync.sh /etc/osync/sync.conf --verbose
```

#### Agendar no cron:

```bash
crontab -e
```

```bash
*/5 * * * * root  bash /usr/local/bin/osync.sh /etc/osync/sync.conf --silent
```

#### Validando os logs em tempo real, rode o /usr/local/bin/osync.sh, mantendo outro terminal aberto com o comando:

```bash
tail -f /var/log/osync.sysvol_sync.log
```

THAT’S ALL FOLKS!!

# Servidor de Arquivos com Samba4 no Debian 12

#### Layout de rede usado no laboratório:

```bash
firewall        192.168.70.254 (enp1s0) - 192.168.0.254 (enp7s0) (ssh 22254)
pdc01           192.168.70.253   (ssh 22253)
pdc02           192.168.70.252   (ssh 22252)
intranet        192.168.70.251   (ssh 22251)
arquivos        192.168.70.250   (ssh 22250)

; firewall      Servidor Firewall OPNSense
; pdc01         Controlador de Domínio primário
; pdc02         Controlador de Domínio secundário
; intranet      Servidor de Intranet
; arquivos      Servidor de Arquivos
```

#### Instalando as dependências para compilação do código fonte  do Samba4:

```bash
export DEBIAN_FRONTEND=noninteractive;apt-get update; apt-get install vim net-tools rsync acl apt-utils attr autoconf bind9-utils binutils bison build-essential rsync ccache chrpath curl debhelper bind9-dnsutils docbook-xml docbook-xsl flex gcc gdb git glusterfs-common gzip heimdal-multidev hostname htop krb5-config krb5-user lcov libacl1-dev libarchive-dev libattr1-dev libavahi-common-dev libblkid-dev libbsd-dev libcap-dev libcephfs-dev libcups2-dev libdbus-1-dev libglib2.0-dev libgnutls28-dev libgpgme-dev libicu-dev libjansson-dev libjs-jquery libjson-perl libkrb5-dev libldap2-dev liblmdb-dev libncurses-dev libpam0g-dev libparse-yapp-perl libpcap-dev libpopt-dev libreadline-dev libsystemd-dev libtasn1-bin libtasn1-6-dev libunwind-dev lmdb-utils locales lsb-release make mawk mingw-w64 patch perl perl-modules-5.40 pkg-config procps psmisc python3 python3-cryptography python3-dbg python3-dev python3-dnspython python3-gpg python3-iso8601 python3-markdown python3-matplotlib python3-pexpect python3-pyasn1 rsync sed tar tree uuid-dev wget xfslibs-dev xsltproc zlib1g-dev -y

#### Setando e validando o hostname do pdc02:

```bash
vim /etc/hostname
```

```bash
arquivos
```

```bash
hostname -f
```

```bash
arquivos.officinas.edu
```

#### Configurando o arquivo de hosts:

```bash
vim /etc/hosts
```

```bash
.0.0.1              localhost
127.0.1.1           arquivos.officinas.edu    arquivos
192.168.70.250      arquivos.officinas.edu    arquivos
```

#### Setando ip fixo no servidor pdc02:

```bash
vim /etc/network/interfaces
```

```bash
allow-hotplug enp1s0
iface enp1s0 inet static
address           192.168.70.250
netmask           255.255.255.0
gateway           192.168.70.254
```

#### Apontando o endereço do resolvedor de nomes principal da rede pro Controlador de domínio primário, pdc01 (temporário):

```bash
vim /etc/resolv.conf
```

```bash
domain           officinas.edu
search           officinas.edu.
nameserver       192.168.70.253
nameserver       192.168.70.252
```

#### Bloqueando alteração do resolv.conf:

```bash
chattr +i /etc/resolv.conf
```

#### Validando a resolução de nomes pelo pdc01:

```bash
nslookup officinas.edu
```

```bash
Server:         192.168.70.253
Address:        192.168.70.253#53

Name:   officinas.edu
Address: 192.168.70.253
```

#### Relendo as configurações de rede:

```bash
systemctl restart networking
```

#### Validando o ip da placa:

```bash
ip -c addr
```

```bash
ip -br link
```

#### Baixando e compilando o código fonte do Samba4:

```bash
wget https://download.samba.org/pub/samba/samba-4.22.3.tar.gz
```

```bash
tar -xvzf samba-4.22.3.tar.gz
```

```bash
cd samba-4.22.3
```

```bash
./configure --prefix=/opt/samba \
  --with-winbind \
  --with-shared-modules=idmap_rid,idmap_ad
```

```bash
make -j$(nproc)
```

```bash
make install
```

```bash
make clean
```

#### Validar se o winbind e NSS foram compilados

```bash
/opt/samba/sbin/smbd -b | grep WINBIND
```

```bash
WITH_WINBIND
```

```bash
/opt/samba/sbin/smbd -b | grep LIBDIR
```

```bash
LIBDIR: /opt/samba/lib
```

```bash
find /opt/samba -name "libnss_winbind.so*"
```

```bash
/opt/samba/lib/libnss_winbind.so.2
```

## Linkar as bibliotecas compiladas do Winbind e NSS ao path do Sistema Operacional (rode esses comandos manualmente sem copiar e colar):

```bash
ln -s /opt/samba/lib/libnss_winbind.so.2 /lib/x86_64-linux-gnu
```

```bash
ln -s /lib/x86_64-linux-gnu/libnss_winbind.so.2 /lib/x86_64-linux-gnu/libnss_winbind.so
```

```bash
ldconfig
```

#### Adicionando /opt/Samba ao path padrão do Linux, colando a linha completa ao final do .bashrc:

#### PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/samba/bin:/opt/samba/sbin"

```bash
vim ~/.bashrc
```

```bash
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/samba/bin:/opt/samba/sbin"
```

#### Relendo o arquivo de profile:

```bash
source ~/.bashrc
```

#### ATENÇÃO!! NÃO PROVISIONE O SAMBA DO arquivos!!

#### ATENÇÃO!! NÃO PROVISIONE O SAMBA DO arquivos!!

#### 

#### Configurando o /etc/krb5.conf:

```bash
# vim /etc/krb5.conf
```

```bash
[libdefaults] #(sem espaço no canto dessa linha)
   dns_lookup_realm = false
   dns_lookup_kdc = true
   default_realm = OFFICINAS.EDU
```

#### Validando mapeamentos:

```bash
getent hosts arquivos
```

#### Configurando o smb.conf:

```bash
# vim /opt/samba/etc/smb.conf
```

```bash
# Define as informações do domínio.
   [global]
   workgroup = OFFICINAS
   realm = officinas.edu
   encrypt passwords = yes

# Define que esse servidor não aceita acesso sem autenticação.
    security = ADS

# Defique qual usuário no domínio se equivale ao root.
    username map = /opt/samba/etc/user.map

# Parâmetros para que as permissões se comportem como o Windows.
# Herdando permissões e guardando credenciais de logins bem-sucedidos.
    map acl inherit = yes
    store dos attributes = yes

# Os VFS objects que serão usados.
    vfs objects = acl_xattr acl_tdb

# Arquivo de configuração do kerberos e qual método será usado.
    dedicated keytab file = /etc/krb5.keytab
    kerberos method = secrets and keytab

# Configurações do backend para mapeamento de IDs para compatibilidade com Windows.
    idmap config * : backend = tdb
    idmap config * : range = 3000-7999
    idmap config OFFICINAS: backend = rid
    idmap config OFFICINAS: range = 10000-999999

# Define que o usuário root não precisa ser mapeado.
    min domain uid = 0

# Shell padrão e diretório home padrão.
    template shell = /bin/bash
    template homedir = /home/%U

# Define o comportamento do Winbind.
    winbind refresh tickets = yes
    winbind use default domain = yes
    winbind enum users = yes
    winbind enum groups = yes
    winbind cache time = 7200
    winbind nss info = rfc2307

# Cada escrita  de dados será seguida por um fsync() para garantir que os dados sejam gravados no disco. Usei em ext4 e xfs mas não testei no btrfs.
   sync always = yes
   strict sync = yes

# Onde serão gravados os logs e o nivel de detalhes.
   log file = /opt/samba/var/log.%m
   log level = 3
   max log size = 50

[arquivos]
    path = /srv/arquivos
    comment = Compartilhamentos da Rede
    read only = No
    browseable = yes
    writable = yes
    guest ok = no
    create mask = 0660
    directory mask = 0770
    vfs objects = acl_xattr acl_tdb full_audit
    map acl inherit = yes
    store dos attributes = yes
    full_audit:success = renameat rewinddir unlinkat
    full_audit:prefix = %U|%I|%S
    full_audit:failure = none
    full_audit:facility = local4
    full_audit:priority = alert
    %U|%I|%S

# PARÂMETROS USADOS NA AUDITORIA:
# Adiciona todos os vfs objects.
#   acl_xattr acl_tdb full_audit

# arquivos renomeados, diretórios renomeados, arquivos deletados.
#   renameat rewinddir unlinkat

#   usuário, ip, ação.
#   %U|%I|%S
```

#### Criando o diretório de logs do samba:

```bash
mkdir -p /opt/samba/var/log/
```

# VALIDAR ISSO!!

#### Auditando arquivos deletados:

```bash
cat /var/log/syslog | grep unlinkat
```

```bash
tail -f /var/log/syslog | grep unlinkat #(Teste em tempo real).
```

##### Setando ordenação de autenticação para winbind

```bash
vim /etc/nsswitch.conf
```

```bash
   passwd: files systemd winbind
   group: files systemd winbind
   shadow: files
```

#### Dando poderes de root ao Administrator:

```bash
vim /opt/samba/etc/user.map
```

```bash
!root=officinas.edu\Administrator
```

#### Validando a troca de tickets do Kerberos:

```bash
kinit Administrator
```

```bash
klist
```

```bash
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: Administrator@OFFICINAS.EDU

Valid starting       Expires              Service principal
16/07/2025 14:01:09  17/07/2025 00:01:09  krbtgt/OFFICINAS.EDU@OFFICINAS.EDU
    renew until 17/07/2025 14:01:04
```

#### Ingressando o arquivos ao domínio:

```bash
net ads join -U Administrator
```

```bash
Password for [OFFICINAS\Administrator]:
Using short domain name -- OFFICINAS
Joined 'ARQUIVOS' to dns domain 'officinas.edu'
```

#### Adicionando o SMBD ao boot do Linux:

```bash
cd /etc/systemd/system
```

```bash
vim smbd.service
```

```bash
[Unit]
   Description=Samba SMBD arquivos
   After=network.target remote-fs.target nss-lookup.target

[Service]
   Type=forking
   ExecStart=/opt/samba/sbin/smbd
   ExecReload=/opt/samba/sbin/smbd -s /opt/samba/etc/smb.conf --reload
   ExecStop=/opt/samba/sbin/smbd --terminate
   PIDFile=/opt/samba/var/run/smbd.pid

[Install]
   WantedBy=multi-user.target
```

#### Adicionando o NMBD ao boot do Linux:

```bash
cd /etc/systemd/system
```

```bash
vim nmbd.service
```

```bash
[Unit]
   Description=Samba NMBD arquivos
   After=network.target remote-fs.target nss-lookup.target

[Service]
   Type=forking
   ExecStart=/opt/samba/sbin/nmbd
   ExecStop=/opt/samba/sbin/nmbd --terminate
   PIDFile=/opt/samba/var/run/nmbd.pid

[Install]
   WantedBy=multi-user.target
```

#### Adicionando o WINBIND ao boot do Linux:

```bash
cd /etc/systemd/system
```

```bash
vim winbindd.service
```

```bash
[Unit]
Description=Samba Winbind Daemon
After=network.target nss-lookup.target

[Service]
ExecStart=/opt/samba/sbin/winbindd --foreground --no-process-group
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
PIDFile=/opt/samba/var/run/winbindd.pid

[Install]
WantedBy=multi-user.target
```

#### Habilitndo e subindo os serviços do Sistema:

```bash
systemctl daemon-reexec
systemctl daemon-reload
```

```bash
systemctl enable smbd.service nmbd.service winbindd.service
```

```bash
chmod +x smbd.service nmbd.service winbindd.service
```

```bash
systemctl start smbd.service nmbd.service winbindd.service
```

#### Criando o diretório da rede:

```bash
wbinfo -g | grep -i "domain users"
```

```bash
mkdir -p /srv/arquivos
```

```bash
chmod -R 0770 /srv/arquivos
```

```bash
chown -R root:"Domain users" /srv/arquivos
```

```bash
getfacl /srv/arquivos
```

#### EXTRA! SE optar por uso de perfil móvel:

```bash
mkdir /opt/samba/var/lib/samba/profiles
```

```bash
chmod -R 0770 /opt/samba/var/lib/samba/profiles
```

```bash
chown -R root:"domain admins" /opt/samba/var/lib/samba/profiles
```

#### Validando wbinfo e getent:

```bash
wbinfo --ping-dc
```

```bash
checking the NETLOGON for domain[OFFICINAS] dc connection to "pdc01.officinas.edu" succeeded
```

```bash
wbinfo -u
```

```bash
krbtgt
guest
administrator
```

```bash
wbinfo -g
```

```bash
ras and ias servers
schema admins
denied rodc password replication group
domain users
dnsupdateproxy
enterprise read-only domain controllers
domain admins
group policy creator owners
domain controllers
protected users
enterprise admins
read-only domain controllers
cert publishers
domain guests
allowed rodc password replication group
dnsadmins
domain computers
```

```bash
getent passwd Administrator
```

```bash
administrator:*:10500:10513::/home/administrator:/bin/bash
```

```bash
getent group "domain admins"
```

#### Teste de compartilhamento:

```bash
smbclient //192.168.70.250/arquivos -U OFFICINAS\\administrator
```

#### Criando o script de backup do /srv/arquivos:

```bash
mkdir /media/HDEXTERNO
```

```bash
vim /opt/samba/bkpdiario.sh
```

```bash
#!/bin/bash
   INICIO=`date +%d/%m/%Y-%H:%M:%S`
   LOG=/var/log/samba/bkparquivos_`date +%Y-%m-%d`.txt
   echo " " >> $LOG
   echo " " >> $LOG
   echo "|-----------------------------------------------" >> $LOG
   echo " Sincronizacao iniciada em $INICIO" >> $LOG
   umount /media/HDEXTERNO
   mount /dev/sdb1 /media/HDEXTERNO
   rsync --delete -P -r -z -v /srv/arquivos /media/HDEXTERNO/ >> $LOG
   FINAL=`date +%d/%m/%Y-%H:%M:%S`
   umount /media/HDEXTERNO
   echo " Sincronizacao Finalizada em $FINAL" >> $LOG
   echo "|-----------------------------------------------" >> $LOG
   echo " " >> $LOG
   echo " " >> $LOG
```

#### Adicionando o script ao crontab:

```bash
vim /etc/crontab
```

```bash
# Rotinas de backup diário do SAMBA4.
# Minuto/Hora/Dia/Mês/Dia_semana/Usuário/Comando
   45 23 * * 1-5 root /opt/samba/bkpdiario.sh  > /dev/null 2>&1
```

#### VAI MONTAR O HD EXTERNO, FAZER O BACKUP E DESMONTAR O HD EXTERNO!

THAT’S ALL FOLKS!!
