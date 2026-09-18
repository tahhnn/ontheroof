# May tan cong gia lap - "bot" cua ke tan cong trong mang doanh nghiep SMB.
# Chi dung trong lab do an de kiem thu kha nang phat hien cua SIEM.
FROM kalilinux/kali-rolling

ARG DEBIAN_FRONTEND=noninteractive

# Cong cu tan cong toi thieu:
#   nmap    - quet cong / do dich vu (recon)
#   hydra   - brute-force SSH
#   sshpass - thu mat khau bang script bash
#   netcat  - kiem tra ket noi
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        hydra \
        sshpass \
        netcat-traditional \
        openssh-client \
        iputils-ping \
        python3 \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/ /opt/attack/
RUN chmod +x /opt/attack/*.sh

WORKDIR /opt/attack
# Giu container song de exec lenh tan cong vao
ENTRYPOINT ["sleep", "infinity"]
