## ⚠ Disclaimer

This tool is intended for security research, training, and authorized
defensive deployments only. Do not deploy it on networks you don't own
or operate. Do not use it to impersonate devices on production OT
networks without explicit written authorization from the network owners.

The author assumes no responsibility for misuse. ICS/OT environments
can include safety-critical systems; deploying decoy devices on the
wrong network can cause real operational impact.

# PLC Honeypot — Siemens S7-1200

Server che impersona un PLC Siemens S7-1200 (CPU 1214C, FW V4.6) e risponde
ai protocolli industriali in modo che Tenable e altri scanner OT lo
identifichino correttamente come tale.

Compatibile anche con Raspberry Pi 4 e superiori.

## Cosa risponde

| Layer | Porta / Protocollo | Implementazione |
|-------|-------------------|-----------------|
| TPKT (RFC 1006) | TCP/102 | parser/wrap nativo |
| COTP CR → CC | TCP/102 | eco dei TSAP |
| S7comm classico (0x32) | TCP/102 | Setup Comm + 8 SZL costruite a mano |
| S7comm-Plus (0x72) | TCP/102 | replay dei template estratti dal pcap |
| Modbus TCP | TCP/502 | FC 0x03 (Read Holding) + 0x2B (Device ID) |
| PROFINET DCP | raw L2 (EtherType 0x8892) | Identify Request → Response |

L'**SZL `0x0011`** è il marker che fa scattare il fingerprint di Tenable
(stringa `6ES7 214-1HG40-0XB0` → CPU 1214C). L'**SZL `0x001C`** rinforza
con `S7-1200`, `Siemens`, e nome stazione.

## Struttura del repo

```
plc-honeypot/
├── plc_honeypot.py            # entry point: orchestra i 3 servizi
├── identity.py                # configurazione del PLC virtuale (modello, FW, ...)
├── extract_recordings.py      # tool offline: estrae template S7+ dal pcap
├── test_honeypot.py           # test client end-to-end (S7 + Modbus)
├── requirements.txt           # dpkt (solo per extract_recordings.py)
├── handlers/                  # logica per ogni protocollo
│   ├── cotp.py                # CR → CC + DT wrapper
│   ├── s7comm.py           # SZL responses (★ fingerprint)
│   ├── s7comm_plus.py              # replay-based S7+
│   ├── modbus.py              # Modbus TCP
│   └── profinet_dcp.py        # PROFINET DCP raw L2
├── parsers/                   # ⚠ usato SOLO da extract_recordings.py
│   └── ...                    #   sul Pi puoi anche cancellarlo
├── tables/                    # ⚠ stessa cosa
│   └── ...
└── recorded/                  # template binari pre-estratti
    ├── s7comm_plus_initsession_response.bin
    ├── s7comm_plus_ip_*.bin
    └── ...
```

## Setup su Raspberry Pi 4

Su Raspberry Pi OS 64-bit (Bookworm o successivi):

```bash
# 1. Dipendenze sistema (Python è già installato in Raspberry Pi OS)
sudo apt update && sudo apt install -y git

# 2. Clone del repo
git clone https://github.com/StefanK999/plc-honeypot.git ~/plc-honeypot
cd ~/plc-honeypot

# 3. Passaggio opzionale per abilitare il parser
#    Niente dipendenze Python a runtime: asyncio è nella stdlib.
#    dpkt serve SOLO se vuoi rigenerare i template:
# pip install -r requirements.txt --break-system-packages

# 4. Configura l'identità del PLC virtuale
nano identity.py
# Modifiche consigliate: advertised_ip, advertised_netmask, advertised_gateway
# con i valori reali della rete del Pi.
```

## Avvio manuale

Le porte 102 e 502 sono privilegiate (< 1024) e DCP richiede raw socket.
Tre opzioni:

### A) Capability sul binario (consigliato)
```bash
sudo setcap 'cap_net_bind_service=+ep cap_net_raw=+ep' \
    $(readlink -f $(which python3))
python3 plc_honeypot.py
```

### B) sudo diretto (rapido, sviluppo)
```bash
sudo python3 plc_honeypot.py
```

### C) Porte alte + iptables (più sicuro)
In `identity.py` imposta `s7_port = 10102`, `modbus_port = 10502`, e
`enable_dcp = False`. Poi:
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 102 -j REDIRECT --to-port 10102
sudo iptables -t nat -A PREROUTING -p tcp --dport 502 -j REDIRECT --to-port 10502
python3 plc_honeypot.py
```

## Avvio automatico (systemd)

Crea `/etc/systemd/system/plc-honeypot.service`:

```ini
[Unit]
Description=PLC Honeypot Siemens S7-1200
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/plc-honeypot
ExecStart=/usr/bin/python3 /home/pi/plc-honeypot/plc_honeypot.py
Restart=on-failure
RestartSec=5

# Permette il bind a porte < 1024 e raw socket DCP senza root
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW

# Hardening (opzionale)
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Poi:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now plc-honeypot
sudo systemctl status plc-honeypot
sudo journalctl -u plc-honeypot -f       # log in tempo reale
```

## Test in locale

In un altro terminale (sullo stesso Pi o da un'altra macchina sulla rete):

```bash
python3 test_honeypot.py <ip-del-pi>
```

Output atteso:
```
✓ COTP CR → CC
✓ S7 Setup Communication → AckData
✓ SZL 0x0011 → ['6ES7 214-1HG40-0XB0 ', ...]
✓ SZL 0x001C → ['CPU 1214C DC/DC/DC', 'PLC_1', ...]
...
✓ Modbus FC 0x2B: ['Siemens', 'S7-1200', '4.6.0']
```

Per testare con uno scanner reale, basta puntare Tenable Nessus / OT.Security
all'IP del Pi. Verrà identificato come **Siemens S7-1200, CPU 1214C, FW V4.6**.

## Verifica con `s7scan` (opzionale)

[`s7scan`](https://github.com/klsecservices/s7scan) di Kaspersky fa lo
stesso fingerprinting di Tenable. Ottimo per validare:

```bash
git clone https://github.com/klsecservices/s7scan
python3 s7scan/s7scan.py --hosts <ip-del-pi>
# Output atteso: "MLFB: 6ES7 214-1HG40-0XB0"
```

## Personalizzare l'identità

Modifica `identity.py`:

```python
@dataclass
class PLCIdentity:
    article_number : bytes = b"6ES7 214-1HG40-0XB0 "    # cambia per altro modello
    firmware       : bytes = b"V4.6.0"
    serial_number  : bytes = b"S C-XXXXXXXX"
    advertised_ip  : str   = "192.168.1.42"             # IP del tuo Pi
```

Per impersonare un **S7-1500** servirebbe anche ricatturare i template S7+
da un device reale (i firmware più recenti usano integrità più aggressiva).
Vedi sezione successiva.

## Rigenerare i template da un nuovo pcap

Se hai catturato traffico da un PLC diverso e vuoi rigenerare la
cartella `recorded/`:

```bash
# Sul PC di sviluppo (NON serve sul Pi):
pip install dpkt --break-system-packages
python3 extract_recordings.py path/al/tuo.pcapng <ip-del-plc>
```

Poi committa la nuova cartella `recorded/` nel git e ridepoya sul Pi.

## Limiti noti

1. **HMAC S7+ non valido.** Il replay funziona per il fingerprinting (Tenable
   non verifica la firma in fase di discovery), ma fallirebbe per
   read/write autenticati di variabili.

2. **SZL parziali.** `0x0011` e `0x001C` sono robuste (Tenable se ne
   accontenta); le altre (0x0037, 0x0013, ecc.) sono "binario plausibile"
   non basato sulla tabella ufficiale Siemens. Scanner più approfonditi
   potrebbero notare i campi mancanti.

3. **Detectabile come honeypot** se uno scanner fa cose troppo interattive
   (lettura DB specifici, download blocchi). Il replay statico non basta.
   Per migliorare: integrare il backend `python-snap7 Server` per
   read/write su DB veri (snap7 supporta solo S7 classico).

4. **PROFINET DCP non risponde a tutti i tipi di Identify.** Implementati
   solo i blocchi 0x02/0x01-02-03 e 0x01/0x01 (NameOfStation, DeviceID,
   DeviceRole, IPParameter). Per scanner che cercano DeviceOptions o
   DeviceInstance servirebbero blocchi aggiuntivi.

## Avvertenze

- **Non collegare alla VLAN OT di produzione** senza isolamento. Un PLC
  reale e uno virtuale sulla stessa VLAN possono confondere TIA Portal
  (proverà a connettersi a entrambi).
- **Comunica al SOC prima del deploy.** Anche un honeypot interno può
  essere flaggato come "rogue device" da SIEM/NDR.
- **Tieni i log.** Il valore reale di un honeypot è vedere chi ti
  scansiona — `journalctl -u plc-honeypot` è il primo posto da guardare.

## Idee di estensione

- Logger CSV/JSON di tutti gli scan ricevuti (threat intel)
- Webhook su Telegram/Discord all'arrivo di una connessione
- Modalità "deception": dopo il fingerprint fingere CPU in STOP
- Geo-IP lookup degli IP che si connettono