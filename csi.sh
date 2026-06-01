#!/bin/bash
# CSI Scanner - cPanel Security Investigator
# Version: 1.1
# AUTHOR : Arief Purnomo
# SOURCE RISET :
#  - https://github.com/CpanelInc/tech-CSI
#  - https://docs.cpanel.net/knowledge-base/security/determine-your-system-status/

set -euo pipefail  # Fail-fast: exit on error, undefined var, pipe failure

# --- KONFIGURASI ---
readonly EMAIL_TO="email@email.co.id"
readonly HOSTNAME=$(hostname)
readonly DATE=$(date '+%Y-%m-%d %H:%M:%S')
readonly CSI_DIR="/root/CSI" # Direktori default csi.p dari pihak cPanel.
readonly CSI_SUMMARY="${CSI_DIR}/summary.txt"
readonly CSI_LOG="${CSI_DIR}/csi.log"
readonly SCRIPT_LOG="${CSI_DIR}/csi_scan.log"
readonly PERL_BIN="/usr/local/cpanel/3rdparty/bin/perl"
readonly CSI_URL="https://raw.githubusercontent.com/cPanelTechs/CSI/master/csi.pl"
readonly CSI_CHECKSUM_URL="${CSI_URL}.sha256"  # Opsional: untuk verifikasi
readonly MAX_WAIT=7200  # 2 jam timeout
readonly POLL_INTERVAL=10

# LOGGING
log() {
    local level="${2:-INFO}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] $1" | tee -a "$SCRIPT_LOG"
}

#CLEANUP TRAP
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log "Script terminated unexpectedly (exit code: $exit_code)" "ERROR"
    fi
    # Tambahkan cleanup temp file jika ada
}
trap cleanup EXIT INT TERM

#VALIDASI PRASYARAT
validate_prerequisites() {
    if [[ ! -x "$PERL_BIN" ]]; then
        log "Perl cPanel tidak ditemukan di $PERL_BIN" "ERROR"
        exit 1
    fi

    if ! command -v mail &>/dev/null && ! command -v sendmail &>/dev/null; then
        log "Perintah mail/sendmail tidak ditemukan. Pastikan Exim aktif." "ERROR"
        exit 1
    fi

    if [[ ! -d "$CSI_DIR" ]]; then
        mkdir -p "$CSI_DIR" || {
            log "Gagal membuat direktori $CSI_DIR" "ERROR"
            exit 1
        }
    fi
}

# DOWNLOAD & VERIFIKASI CSI (Opsional)
download_csi_script() {
    local temp_script
    temp_script=$(mktemp) || {
        log "Gagal membuat temporary file" "ERROR"
        return 1
    }

    if ! curl -sL --fail -o "$temp_script" "$CSI_URL"; then
        log "Gagal mendownload CSI script dari $CSI_URL" "ERROR"
        rm -f "$temp_script"
        return 1
    fi

    # Opsional: Verifikasi checksum jika tersedia
    if curl -sL --fail -o "${temp_script}.sha256" "$CSI_CHECKSUM_URL" 2>/dev/null; then
        local expected_checksum
        expected_checksum=$(awk '{print $1}' "${temp_script}.sha256")
        local actual_checksum
        actual_checksum=$(sha256sum "$temp_script" | awk '{print $1}')
        
        if [[ "$expected_checksum" != "$actual_checksum" ]]; then
            log "Checksum mismatch! Script mungkin telah dimodifikasi." "CRITICAL"
            rm -f "$temp_script" "${temp_script}.sha256"
            return 1
        fi
        log "Checksum verified successfully" "INFO"
        rm -f "${temp_script}.sha256"
    else
        log "Checksum file tidak tersedia, melanjutkan tanpa verifikasi" "WARNING"
    fi

    echo "$temp_script"
}

#KIRIM EMAIL
send_email_report() {
    local subject="$1"
    local body="$2"
    
    if printf '%s\n' "$body" | mail -s "$subject" "$EMAIL_TO" 2>/dev/null; then
        log "Email berhasil dikirim ke $EMAIL_TO" "INFO"
        log "Subject: $subject" "INFO"
        return 0
    else
        log "Gagal mengirim email (exit code: $?)" "ERROR"
        return 1
    fi
}

# MAIN EXECUTION
main() {
    validate_prerequisites
    
    log "Memulai CSI scan pada $HOSTNAME" "INFO"
    log "Estimasi durasi: ~1-2 jam tergantung jumlah akun" "INFO"

    # Download script dengan verifikasi
    local csi_script
    csi_script=$(download_csi_script) || {
        send_error_email "Download CSI script gagal"
        exit 1
    }

    # Jalankan CSI scan
    # Note: CSI.pl biasanya butuh file path, bukan process substitution
    if ! "$PERL_BIN" "$csi_script" --overwrite >> "$SCRIPT_LOG" 2>&1; then
        local scan_exit=$?
        log "CSI scan selesai dengan exit code: $scan_exit" "WARNING"
    fi

    # Tunggu CSI selesai menulis output
    log "Menunggu CSI menyelesaikan penulisan log..." "INFO"
    local wait_count=0
    
    while [[ $wait_count -lt $MAX_WAIT ]]; do
        if [[ -f "$CSI_LOG" ]] && grep -q "COMPLETED CSI" "$CSI_LOG" 2>/dev/null; then
            log "CSI scan terdeteksi selesai." "INFO"
            break
        fi
        sleep "$POLL_INTERVAL"
        wait_count=$((wait_count + POLL_INTERVAL))
        # Progress log setiap 5 menit
        if (( wait_count % 300 == 0 )); then
            log "Masih menunggu... (${wait_count}s/${MAX_WAIT}s)" "DEBUG"
        fi
    done

    if [[ $wait_count -ge $MAX_WAIT ]]; then
        log "Timeout setelah ${MAX_WAIT}s. Melanjutkan dengan hasil yang ada..." "WARNING"
    fi

    # Cleanup temp script
    rm -f "$csi_script"

    # Validasi output
    if [[ ! -f "$CSI_SUMMARY" ]]; then
        log "File summary tidak ditemukan: $CSI_SUMMARY" "ERROR"
        send_error_email "CSI scan gagal - summary.txt tidak ditemukan"
        exit 1
    fi

    process_and_send_report
}

#PROSES & KIRIM LAPORAN
process_and_send_report() {
    log "Memproses hasil scan..." "INFO"

    # Extract elapsed time
    local elapsed="tidak diketahui"
    if [[ -f "$CSI_LOG" ]]; then
        elapsed=$(grep "Elapsed Time:" "$CSI_LOG" 2>/dev/null | tail -1 | sed 's/.*Elapsed Time: //' || echo "tidak diketahui")
    fi

    # Deteksi status keamanan
    local has_warnings=false
    local has_critical=false

    if grep -q "WARNINGS" "$CSI_SUMMARY" 2>/dev/null; then
        has_warnings=true
    fi

    # Keywords critical (case-insensitive)
    local -a critical_keywords=(
        "rootkit" "backdoor" "malware" "infected" "exploit" 
        "suspicious binary" "BPFDoor" "ransomware" "Ebury" 
        "DANGER!" "unowned" "compromised openssh"
    )

    for keyword in "${critical_keywords[@]}"; do
        if grep -qi "$keyword" "$CSI_SUMMARY" 2>/dev/null; then
            has_critical=true
            log "Critical keyword terdeteksi: $keyword" "ALERT"
            break
        fi
    done

    # Tentukan label status
    local status_label
    if $has_critical; then
        status_label="[CRITICAL]"
    elif $has_warnings; then
        status_label="[WARNING]"
    else
        status_label="[OK]"
    fi

    # Konten email
    local subject="CSI SCAN - ${status_label} - ${HOSTNAME}"
    
    # Gunakan heredoc untuk body email yang lebih aman
    local email_body
    email_body=$(cat <<EOF
Server        : ${HOSTNAME}
Waktu         : ${DATE}
Status        : ${status_label}
Durasi Scan   : ${elapsed}

=== CSI SUMMARY OUTPUT ===
$(cat "$CSI_SUMMARY")
EOF
)

    log "Mengirim laporan ke $EMAIL_TO dengan status $status_label" "INFO"
    
    if send_email_report "$subject" "$email_body"; then
        log "Proses selesai." "INFO"
        exit 0
    else
        exit 1
    fi
}

#EMAIL ERROR
send_error_email() {
    local error_msg="$1"
    local subject="[CSI SCAN ERROR] ${HOSTNAME} - ${DATE}"
    local body
    body=$(cat <<EOF
CSI scan mengalami kesalahan.

Server : ${HOSTNAME}
Waktu  : ${DATE}
Error  : ${error_msg}

Silakan cek log di: ${SCRIPT_LOG}
EOF
)
    send_email_report "$subject" "$body" || true  # Jangan fail jika email error juga gagal
}

#ENTRY POINT
main "$@"
