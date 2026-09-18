# Endpoint gia lap de cai Wazuh agent thu cong - dung cho do an SIEM.
# Khong cai san agent: nguoi dung tu vao container chay dpkg -i de thay quy trinh onboarding.
FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

# Goi toi thieu cho: cai .deb (dpkg), agent chay (libc, procps),
# tao log that de agent doc (rsyslog, openssh-server), va tien debug (curl, vim, net-tools).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        procps \
        net-tools \
        iputils-ping \
        vim-tiny \
        less \
        rsyslog \
        openssh-server \
        sudo \
        python3 \
        cron \
    && rm -rf /var/lib/apt/lists/*

# sshd can thu muc runtime + host key; login that se sinh log /var/log/auth.log
RUN mkdir -p /var/run/sshd \
    && ssh-keygen -A \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config \
    && echo 'root:Endpoint123!' | chpasswd

# rsyslog trong container khong co /dev/log tu systemd -> tu tao imuxsock la du.
# Tat imklog vi container khong doc duoc kernel log.
RUN sed -i 's/^module(load="imklog")/#module(load="imklog")/' /etc/rsyslog.conf \
    && sed -i 's/^\$ModLoad imklog/#$ModLoad imklog/' /etc/rsyslog.conf

# Tai khoan nghiep vu de thu brute-force SSH tu container khac.
# ketoan1 duoc cap sudo - mo phong server cau hinh sai (nhan vien nghiep vu co
# quyen root). Dung cho kich ban leo thang quyen: sudo len root -> rule 5402/5403.
RUN useradd -m -s /bin/bash ketoan1 && echo 'ketoan1:Ketoan@123' | chpasswd \
    && useradd -m -s /bin/bash nvhung  && echo 'nvhung:Nvhung@123' | chpasswd \
    && usermod -aG sudo ketoan1 \
    && echo 'ketoan1 ALL=(ALL) ALL' > /etc/sudoers.d/ketoan1 && chmod 440 /etc/sudoers.d/ketoan1

# Thu muc cau hinh ERP - muc tieu FIM realtime. Kich ban leo quyen ghi backdoor
# vao day -> syscheck alert (rule.groups: syscheck) -> giai doan 2 cua rule tuong
# quan privilege_then_config_change. Bat FIM realtime bang config/fim-realtime.xml.
RUN mkdir -p /etc/erpapp && echo 'db_host=10.10.10.5' > /etc/erpapp/config.conf

# User/group he dieu hanh cho Wazuh agent - TAO SAN voi uid 103 / gid 104 co dinh.
# postinst cua goi .deb cung tao user nay nhung ghi vao lop ghi cua container.
# /var/ossec nam tren named volume: khi container bi recreate (compose up --build),
# file agent con nguyen (uid 103:104) nhung user OS mat -> execd chet
# "Invalid user '' or group 'wazuh'" va agentd loi "Permission denied queue/rids".
# Tao san o tang image dam bao uid/gid luon khop du container tao lai bao nhieu lan.
RUN groupadd -g 104 wazuh \
    && useradd -u 103 -g 104 -d /var/ossec -s /sbin/nologin wazuh

COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY scripts/app-logger.py /usr/local/bin/app-logger.py
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/app-logger.py

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
