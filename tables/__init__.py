# ─────────────────────────────────────────────────────────────────────────────
# tables/__init__.py
# Tabelle di lookup ricavate dal reverse engineering del PCAP
# + documentazione pubblica S7comm (WireShark, reverse engineering community)
# ─────────────────────────────────────────────────────────────────────────────

# ── COTP PDU types (ISO 8073 / X.224) ────────────────────────────────────────
COTP_PDU_TYPES = {
    0xE0: "CR  (Connection Request)",
    0xD0: "CC  (Connection Confirm)",
    0x80: "DR  (Disconnect Request)",
    0x70: "DC  (Disconnect Confirm)",
    0xF0: "DT  (Data Transfer)",
    0x60: "AK  (Data Acknowledge)",
    0x50: "EA  (Expedited Ack)",
    0x40: "ED  (Expedited Data)",
    0x10: "RJ  (Reject)",
    0x20: "ER  (TPDU Error)",
}

COTP_PARAM_CODES = {
    0xC0: "TPDU-Size",
    0xC1: "Calling-TSAP (src)",
    0xC2: "Called-TSAP  (dst)",
    0xC3: "Checksum",
    0x85: "Version number",
    0x46: "Flow control confirmation",
    0xBE: "Additional option selection",
}

TPDU_SIZES = {
    0x07: 128,
    0x08: 256,
    0x09: 512,
    0x0A: 1024,
    0x0B: 2048,
    0x0C: 4096,
    0x0D: 8192,
}

# ── S7comm ROSCTR (tipo di PDU) ───────────────────────────────────────────────
S7_ROSCTR = {
    0x01: "Job         (richiesta)",
    0x02: "Ack         (conferma senza dati)",
    0x03: "Ack-Data    (risposta con dati)",
    0x07: "UserData    (estensioni CPU/Diagnostic)",
}

# ── S7comm Function codes (campo 'function' nel Parameter Header) ─────────────
S7_FUNCTIONS = {
    0xF0: "Setup Communication   → negozia dimensione PDU e code",
    0x04: "Read Variable",
    0x05: "Write Variable",
    0x1A: "Request Download",
    0x1B: "Download Block",
    0x1C: "Download Ended",
    0x1D: "Start Upload",
    0x1E: "Upload",
    0x1F: "End Upload",
    0x28: "PI Service            (avvia/stoppa CPU, reset)",
    0x29: "PLC Stop",
}

# ── S7comm UserData - Type ID ─────────────────────────────────────────────────
S7_USERDATA_TYPE = {
    0x11: "CPU Functions / Diagnostic",
    0x12: "Cyclic services",
    0x13: "Block functions",
    0x14: "CPU clock/time",
    0x15: "Security",
    0x19: "Time-of-day",
    0x1C: "Notify / Event",
    0x1D: "Message functions",
    0x1E: "Diagnostic message",
}

# ── S7comm UserData - Function Groups ─────────────────────────────────────────
S7_USERDATA_FUNCGROUP = {
    0x44: "Read SZL (System State List)",
    0x45: "Message services",
    0x46: "Clock/Timestamp",
}

# ── SZL IDs → significato (dall'analisi del PCAP + doc pubblica Siemens) ──────
# Nella cattura: 0x0011, 0x0013, 0x001C, 0x0037 sono quelli osservati
SZL_IDS = {
    0x0000: "ID e indice SZL completi",
    0x0011: "Identification del modulo (numero d'ordine, modello CPU)",
    0x0012: "Caratteristiche del modulo",
    0x0013: "Memory card / flash identification",
    0x0014: "Dati identificazione CPU",
    0x001C: "Component identification (nome stazione, nome modulo, firmware)",
    0x0019: "CPU State",
    0x0021: "Online information",
    0x0025: "Status della funzionalità di processo",
    0x0031: "Communication capabilities",
    0x0037: "Stato operativo della CPU",
    0x0074: "Dati moduli / rack",
    0x0091: "Module status information",
    0x00B1: "DP master configuration",
    0x00B4: "Slave / IO configuration",
    0x0111: "Module identification for all modules",
    0x0131: "Communication status data",
    0x0174: "Extended hardware identification",
    0x0222: "Interrupt status",
    0x0232: "Interrupt S7-400 info",
    0x0524: "CPU message functions status",
    0x0A00: "Diagnostic hardware sub-modules",
    0x0D91: "Module diagnostic (PROFIBUS)",
    0x0F00: "Diagnostic buffer: all entries",
    0x0F01: "Diagnostic buffer: start/stop events",
    0xD000: "SZL partial list overview",
}

SZL_INDEX_DESC = {
    0x0000: "Modulo base / CPU",
    0x0001: "Modulo opzionale / espansione 1",
    0x0002: "Modulo espansione 2",
}

# ── S7comm-Plus: tipi di PDU (protocollo 0x72, TIA Portal) ───────────────────
S7PLUS_PDU_TYPE = {
    0x31: "Request    (Tenable → PLC)",
    0x32: "Response   (PLC → Tenable)",
    0x33: "Notification",
    0x20: "Integrity-Protected (wrapper)",
}

# ── S7comm-Plus Function Codes ────────────────────────────────────────────────
# Ricavati incrociando: dissector Wireshark (packet-s7comm_plus.c),
# progetto Cassandra, e osservazione diretta del PCAP.
# Note: l'identificazione di alcuni codici è tentativa — in S7+ i nomi
# variano leggermente tra firmware. Quelli marcati [obs] li abbiamo
# visti nel nostro traffico Tenable↔PLC.
S7PLUS_FUNCTIONS = {
    0x04BB: "Explore                  (browse oggetti del PLC)",
    0x04CA: "InitSession / GetMultiVar (apertura sessione + lettura iniziale)  [obs]",
    0x04D4: "SetMultiVariables        (scrittura multipla)                     [obs]",
    0x04E8: "SetVariable              (scrittura singola)",
    0x04F2: "GetLink                  (interrogazione link)",
    0x0524: "GetVarSubStreamed        (lettura stream)",
    0x0542: "SetVarSubStreamed        (scrittura stream / subscription)        [obs]",
    0x0586: "GetVariablesAddrList     (lettura lista variabili)                [obs]",
    0x05D2: "BeginSequence",
    0x05DD: "EndSequence",
    0x05E8: "Invoke",
    0x05F2: "DeleteObject             (chiusura oggetto / fine sessione)       [obs]",
}

# Lunghezza tipica dell'integrity block dentro un PDU 0x20.
# Determinata empiricamente dal PCAP: dopo il byte di opcode 0x20 ci sono
# 32 byte molto entropici prima che ricompaia un opcode interno (0x31/0x32).
S7PLUS_INTEGRITY_BLOCK_LEN = 32

# ── Mapping TSAP → ruolo funzionale ──────────────────────────────────────────
TSAP_MEANINGS = {
    b'\x01\x00': "PG/PC Communication (Programmazione / Engineering)",
    b'\x01\x01': "PG/PC (slot alternativo)",
    b'\x02\x00': "OP Communication (HMI / pannello operatore)",
    b'\x03\x00': "S7 Basic Communication",
}

TSAP_STRING_MEANINGS = {
    "SIMATIC-ROOT-ES": "TIA Portal Engineering Station root object",
}

# ── Transport sizes S7comm ────────────────────────────────────────────────────
S7_TRANSPORT_SIZE = {
    0x00: "NULL",
    0x01: "BIT",
    0x02: "BYTE (1 byte)",
    0x03: "CHAR",
    0x04: "WORD (2 bytes)",
    0x05: "INT",
    0x06: "DWORD (4 bytes)",
    0x07: "DINT",
    0x08: "REAL",
    0x09: "OCTET STRING (byte grezzo)",
    0x0A: "DATE",
    0x0B: "TIME_OF_DAY",
    0x0C: "TIME",
    0x0D: "S5TIME",
    0x0F: "DATE_AND_TIME",
    0x1C: "Counter",
    0x1D: "Timer",
    0x1E: "IEC Timer",
    0x1F: "IEC Counter",
}

# ── Return codes S7comm ───────────────────────────────────────────────────────
S7_RETURN_CODES = {
    0x00: "Reserved",
    0x01: "Hardware error",
    0x03: "Access error",
    0x05: "Invalid address",
    0x06: "Data type not supported",
    0x07: "Data type inconsistent",
    0x0A: "Object does not exist",
    0x0B: "Temporarily not available",
    0xFF: "Success",
}
