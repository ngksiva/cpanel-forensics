#!/bin/bash
# ============================================================
# cpanel_forensics.sh — Форензика после CVE-2026-41940
# cPanel/WHM + MySQL/MariaDB
# Автор: Батранков Денис · t.me/safebdv
# Версия: 1.0 · Май 2026
#
# Запуск: sudo bash cpanel_forensics.sh
# Отчёт сохраняется в: /tmp/forensics_report_ДАТА.txt
# ============================================================

set -euo pipefail

# ── Цвета ────────────────────────────────────────────────────
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

REPORT="/tmp/forensics_report_$(date +%F_%H%M).txt"
VULN_START="2026-02-23"
VULN_END="2026-04-28"
DAYS=75

# ── Вывод ────────────────────────────────────────────────────
log()  { echo -e "$1" | tee -a "$REPORT"; }
head() { log "\n${BLD}${CYN}══════════════════════════════════════${RST}"; log "${BLD}${CYN}$1${RST}"; log "${CYN}══════════════════════════════════════${RST}"; }
ok()   { log "  ${GRN}✔${RST}  $1"; }
warn() { log "  ${YEL}⚠${RST}  $1"; }
crit() { log "  ${RED}🔴 КРИТИЧНО:${RST} $1"; }
info() { log "  ${CYN}ℹ${RST}  $1"; }
sep()  { log "  ──────────────────────────────────────"; }

# ── Проверка прав ─────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}Запустите скрипт с правами root: sudo bash $0${RST}"
  exit 1
fi

log "============================================================"
log " ФОРЕНЗИКА cPanel/WHM · CVE-2026-41940 · $(date)"
log " Отчёт: $REPORT"
log " Период уязвимости: $VULN_START — $VULN_END"
log "============================================================"

# ════════════════════════════════════════════════════════════
# БЛОК 1: ФАЙЛОВАЯ СИСТЕМА И SSH
# ════════════════════════════════════════════════════════════

head "1/10 · SSH-КЛЮЧИ"

log "\n  [1a] authorized_keys у root:"
sep
if [[ -f /root/.ssh/authorized_keys ]]; then
  KEYS=$(wc -l < /root/.ssh/authorized_keys)
  if [[ $KEYS -gt 0 ]]; then
    warn "Найдено ключей у root: $KEYS — проверьте вручную:"
    cat /root/.ssh/authorized_keys | tee -a "$REPORT" | sed 's/^/    /'
  else
    ok "authorized_keys у root пустой"
  fi
else
  ok "Файл /root/.ssh/authorized_keys отсутствует"
fi

log "\n  [1b] authorized_keys у пользователей /home:"
sep
for u in $(cut -d: -f1,3 /etc/passwd | awk -F: '$2>=1000{print $1}'); do
  f="/home/$u/.ssh/authorized_keys"
  if [[ -f "$f" ]]; then
    K=$(wc -l < "$f")
    warn "Пользователь $u: $K ключ(ей) в $f"
    cat "$f" | tee -a "$REPORT" | sed 's/^/    /'
  fi
done
ok "Проверка SSH-ключей завершена"

# ────────────────────────────────────────────────────────────
head "2/10 · ПОЛЬЗОВАТЕЛИ С UID 0"

EXTRA_ROOT=$(awk -F: '($3==0 && $1!="root")' /etc/passwd)
if [[ -n "$EXTRA_ROOT" ]]; then
  crit "Найдены пользователи с UID 0 кроме root:"
  echo "$EXTRA_ROOT" | tee -a "$REPORT" | sed 's/^/    /'
else
  ok "Только root имеет UID 0"
fi

log "\n  Последние созданные аккаунты (возможные фиктивные):"
sep
awk -F: '{print $1}' /etc/passwd | tail -20 | tee -a "$REPORT" | sed 's/^/    /'

# ────────────────────────────────────────────────────────────
head "3/10 · РУТКИТЫ: ld.so.preload"

if [[ -f /etc/ld.so.preload && -s /etc/ld.so.preload ]]; then
  crit "/etc/ld.so.preload НЕ ПУСТОЙ — вероятен руткит!"
  crit "Все утилиты на этом сервере могут врать. Переходите в rescue-режим провайдера."
  cat /etc/ld.so.preload | tee -a "$REPORT" | sed 's/^/    /'
else
  ok "/etc/ld.so.preload пустой или отсутствует"
fi

# ────────────────────────────────────────────────────────────
head "4/10 · АЛИАСЫ, PATH И ПОДМЕНА КОМАНД"

log "\n  Текущие алиасы:"
sep
alias 2>/dev/null | tee -a "$REPORT" | sed 's/^/    /' || true

log "\n  Пути к системным утилитам (должны быть /bin или /usr/bin):"
sep
for cmd in ls ps top lsof netstat; do
  path=$(which "$cmd" 2>/dev/null || echo "НЕ НАЙДЕН")
  if echo "$path" | grep -qE "^/(bin|usr/bin|usr/sbin|sbin)/"; then
    ok "$cmd → $path"
  else
    warn "$cmd → $path (нестандартный путь!)"
  fi
done

log "\n  PATH:"
echo "$PATH" | tee -a "$REPORT" | sed 's/^/    /'
if echo "$PATH" | grep -qE "(~|/tmp|\.local/bin)"; then
  crit "Подозрительные пути в начале PATH!"
fi

# ────────────────────────────────────────────────────────────
head "5/10 · АВТОЗАГРУЗКА (zsh/bash)"

for f in ~/.zshrc ~/.zshenv /etc/zsh/zshrc /etc/zsh/zshenv \
          /etc/profile /etc/bash.bashrc /root/.bashrc; do
  if [[ -f "$f" ]]; then
    HITS=$(grep -E "eval|base64|curl|wget|python.*-c" "$f" 2>/dev/null | grep -v "^#" || true)
    if [[ -n "$HITS" ]]; then
      warn "Подозрительные строки в $f:"
      echo "$HITS" | tee -a "$REPORT" | sed 's/^/    /'
    else
      ok "$f — чистый"
    fi
  fi
done

# ────────────────────────────────────────────────────────────
head "6/10 · CRON"

log "\n  crontab root:"
sep
crontab -l 2>/dev/null | tee -a "$REPORT" | sed 's/^/    /' || info "crontab root пустой"

log "\n  /etc/crontab и /etc/cron.d/:"
sep
cat /etc/crontab 2>/dev/null | tee -a "$REPORT" | sed 's/^/    /' || true
ls -la /etc/cron.d/ 2>/dev/null | tee -a "$REPORT" | sed 's/^/    /' || true

log "\n  Cron всех пользователей:"
sep
for u in $(cut -d: -f1 /etc/passwd); do
  CTAB=$(crontab -u "$u" -l 2>/dev/null || true)
  if [[ -n "$CTAB" ]]; then
    warn "Пользователь $u имеет crontab:"
    echo "$CTAB" | tee -a "$REPORT" | sed 's/^/    /'
  fi
done

# ────────────────────────────────────────────────────────────
head "7/10 · SYSTEMD-ЮНИТЫ И ПРОЦЕССЫ"

log "\n  Нестандартные запущенные сервисы:"
sep
systemctl list-units --type=service --state=running --no-pager 2>/dev/null \
  | grep -vE "(ssh|cron|mysql|apache|nginx|php|cpanel|rsyslog|network|systemd|dbus|getty)" \
  | tee -a "$REPORT" | sed 's/^/    /' || true

log "\n  Сервисы, добавленные за период уязвимости:"
sep
find /etc/systemd /lib/systemd -name "*.service" -newer /etc/passwd -mtime -"$DAYS" 2>/dev/null \
  | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "Свежих service-файлов не найдено"

log "\n  Процессы с удалённым бинарником (grep deleted):"
sep
ls -la /proc/*/exe 2>/dev/null | grep deleted \
  | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "Процессов с deleted бинарником не найдено"

log "\n  Топ-10 процессов по CPU:"
sep
ps auxwwf | sort -rn -k3 | head -10 | tee -a "$REPORT" | sed 's/^/    /'

# ────────────────────────────────────────────────────────────
head "8/10 · СЕТЬ"

log "\n  Исходящие соединения (ESTABLISHED):"
sep
ss -tnp | grep ESTABLISHED | tee -a "$REPORT" | sed 's/^/    /' || true

log "\n  Открытые порты:"
sep
ss -tulpn | tee -a "$REPORT" | sed 's/^/    /'

log "\n  ELF-бинарники в /tmp и /dev/shm:"
sep
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null \
  | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "Исполняемых файлов в /tmp не найдено"

# ────────────────────────────────────────────────────────────
head "9/10 · ИСТОРИЯ КОМАНД"

for hfile in ~/.zsh_history ~/.bash_history /root/.bash_history /root/.zsh_history; do
  if [[ -f "$hfile" ]]; then
    HITS=$(grep -E "wget|curl|base64|python.*-c|perl.*-e|nc |ncat|/dev/tcp" "$hfile" 2>/dev/null || true)
    if [[ -n "$HITS" ]]; then
      warn "Подозрительные команды в $hfile:"
      echo "$HITS" | tee -a "$REPORT" | sed 's/^/    /'
    else
      ok "$hfile — подозрительных команд не найдено"
    fi
    info "Дата изменения $hfile: $(stat -c '%y' "$hfile" 2>/dev/null)"
  fi
done

# ────────────────────────────────────────────────────────────
head "10/10 · СВЕЖИЕ ФАЙЛЫ И ВЕБ-ШЕЛЛЫ"

log "\n  PHP-файлы новее /etc/passwd в /home и /var/www:"
sep
find /home /var/www -name "*.php" -newer /etc/passwd 2>/dev/null \
  | head -30 | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "Свежих PHP-файлов не найдено"

log "\n  PHP в uploads (там не должно быть .php):"
sep
find /home /var/www -path "*/uploads/*.php" 2>/dev/null \
  | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "PHP в uploads не найден"

log "\n  Поиск eval(base64_decode) в PHP:"
sep
grep -rl "eval(base64_decode" /home /var/www 2>/dev/null \
  | head -20 | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "eval(base64_decode) не найден"

log "\n  Файлы Sorry Ransomware (.sorry):"
sep
find /home /var/www -name "*.sorry" 2>/dev/null \
  | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "Файлов .sorry не найдено"

# ════════════════════════════════════════════════════════════
# БЛОК 2: MySQL / MariaDB
# ════════════════════════════════════════════════════════════

head "БЛОК MySQL: НАЧАЛО"
log "  Проверяем доступность MySQL..."

if ! command -v mysql &>/dev/null; then
  warn "MySQL/MariaDB не найден — пропускаем блок БД"
else

MYSQL_CMD="mysql -N -e"

run_sql() {
  mysql -N -e "$1" 2>/dev/null || warn "Ошибка выполнения запроса: $1"
}

# ── M1. secure_file_priv ─────────────────────────────────────
log "\n${BLD}[M1] Конфигурационный предохранитель: secure_file_priv${RST}"
sep
SFP=$(run_sql "SHOW VARIABLES LIKE 'secure_file_priv';" | awk '{print $2}')
if [[ -z "$SFP" || "$SFP" == "NULL" ]]; then
  ok "secure_file_priv = NULL — запись файлов через SQL заблокирована"
elif [[ "$SFP" == "" ]]; then
  crit "secure_file_priv пустой — запись разрешена в ЛЮБУЮ директорию!"
  crit "Петля самовосстановления через INTO OUTFILE активна."
else
  warn "secure_file_priv = $SFP — запись ограничена этой директорией"
fi

# ── M2. Плагинная директория ─────────────────────────────────
log "\n${BLD}[M2] Директория плагинов MySQL:${RST}"
sep
PLUGIN_DIR=$(run_sql "SHOW VARIABLES LIKE 'plugin_dir';" | awk '{print $2}')
info "plugin_dir = $PLUGIN_DIR"
if [[ -n "$PLUGIN_DIR" ]]; then
  log "\n  Свежие .so файлы в $PLUGIN_DIR:"
  find "$PLUGIN_DIR" -name "*.so" -mtime -"$DAYS" 2>/dev/null \
    | tee -a "$REPORT" | sed 's/^/    /' \
    || ok "Свежих .so файлов не найдено"
fi

# ── M3. UDF функции ──────────────────────────────────────────
log "\n${BLD}[M3] UDF-функции (должна быть пустая таблица):${RST}"
sep
UDF=$(run_sql "SELECT name, dl FROM mysql.func;")
if [[ -n "$UDF" ]]; then
  crit "Найдены UDF-функции:"
  echo "$UDF" | tee -a "$REPORT" | sed 's/^/    /'
else
  ok "mysql.func пустая — UDF не зарегистрированы"
fi

# ── M4. Триггеры ─────────────────────────────────────────────
log "\n${BLD}[M4] Триггеры вне системных схем:${RST}"
sep
TRIGGERS=$(run_sql "SELECT CONCAT(trigger_schema,'.',trigger_name,' | ',event_object_table,' | ',LEFT(action_statement,80))
  FROM information_schema.triggers
  WHERE trigger_schema NOT IN ('mysql','sys','performance_schema');")
if [[ -n "$TRIGGERS" ]]; then
  crit "Найдены нестандартные триггеры:"
  echo "$TRIGGERS" | tee -a "$REPORT" | sed 's/^/    /'
else
  ok "Нестандартных триггеров не найдено"
fi

# ── M5. Хранимые процедуры ───────────────────────────────────
log "\n${BLD}[M5] Хранимые процедуры и функции:${RST}"
sep
PROCS=$(run_sql "SELECT CONCAT(routine_schema,'.',routine_name,' (',routine_type,')')
  FROM information_schema.routines
  WHERE routine_schema NOT IN ('sys','mysql','information_schema');")
if [[ -n "$PROCS" ]]; then
  warn "Найдены хранимые процедуры/функции (проверьте вручную):"
  echo "$PROCS" | tee -a "$REPORT" | sed 's/^/    /'
else
  ok "Нестандартных процедур не найдено"
fi

# ── M6. Опасные привилегии ───────────────────────────────────
log "\n${BLD}[M6] Опасные привилегии (FILE, SUPER, анонимные):${RST}"
sep
PRIVS=$(run_sql "SELECT user, host, File_priv, Super_priv
  FROM mysql.user
  WHERE user = '' OR File_priv = 'Y' OR Super_priv = 'Y';")
if [[ -n "$PRIVS" ]]; then
  crit "Найдены опасные аккаунты:"
  echo "$PRIVS" | tee -a "$REPORT" | sed 's/^/    /'
else
  ok "Опасных привилегий не найдено"
fi

# ── M7. Пользователи по дате создания ───────────────────────
log "\n${BLD}[M7] Пользователи MySQL по дате изменения (ищем февраль–апрель 2026):${RST}"
sep
MYSQL_VER=$(mysql -N -e "SELECT VERSION();" 2>/dev/null | head -1)
info "Версия MySQL/MariaDB: $MYSQL_VER"

# Проверяем наличие столбца password_last_changed
HAS_COL=$(run_sql "SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema='mysql' AND table_name='user'
  AND column_name='password_last_changed';")

if [[ "$HAS_COL" -gt 0 ]]; then
  run_sql "SELECT user, host, password_last_changed FROM mysql.user
    ORDER BY password_last_changed DESC;" \
    | tee -a "$REPORT" | sed 's/^/    /'
  warn "Аккаунты с именами cpanel_backup, mysql_monitor, admin_support, service_account — красный флаг"
else
  warn "Столбец password_last_changed недоступен в этой версии MySQL/MariaDB"
  info "Альтернатива: проверьте время изменения файлов в /var/lib/mysql/mysql/"
  find /var/lib/mysql/mysql -name "*.frm" -o -name "*.ibd" 2>/dev/null \
    | xargs ls -la 2>/dev/null | grep -E "Feb|Mar|Apr" \
    | tee -a "$REPORT" | sed 's/^/    /' || true
fi

# ── M8. Бинарные логи ───────────────────────────────────────
log "\n${BLD}[M8] Бинарные логи (чёрный ящик за 64 дня):${RST}"
sep
LOG_BIN=$(run_sql "SHOW VARIABLES LIKE 'log_bin';" | awk '{print $2}')
if [[ "$LOG_BIN" == "ON" ]]; then
  info "Бинарные логи включены"
  run_sql "SHOW BINARY LOGS;" | tee -a "$REPORT" | sed 's/^/    /' || true
  BINLOG_PATH=$(run_sql "SHOW VARIABLES LIKE 'log_bin_basename';" | awk '{print $2}')
  info "Путь к логам: $BINLOG_PATH"
  log "\n  Анализ бинарных логов за период уязвимости:"
  info "Выполните вручную (логи могут быть большими):"
  log "    mysqlbinlog --start-datetime=\"$VULN_START 00:00:00\" \\"
  log "                --stop-datetime=\"$VULN_END 23:59:59\" \\"
  log "                ${BINLOG_PATH}.* \\"
  log "                | grep -i \"outfile\\|create user\\|grant\\|drop\""
else
  info "Бинарные логи выключены (log_bin=OFF)"
fi

# ── M9. Сетевая активность mysqld ───────────────────────────
log "\n${BLD}[M9] Сетевая активность mysqld:${RST}"
sep
MYSQL_NET=$(ss -tnp | grep mysqld | grep -v "127.0.0.1:3306" || true)
if [[ -n "$MYSQL_NET" ]]; then
  crit "mysqld имеет соединения вне 127.0.0.1:3306:"
  echo "$MYSQL_NET" | tee -a "$REPORT" | sed 's/^/    /'
else
  ok "mysqld слушает только локально — норма"
fi

fi  # конец блока MySQL

# ════════════════════════════════════════════════════════════
# ИТОГОВЫЙ ОТЧЁТ
# ════════════════════════════════════════════════════════════

head "ИТОГ"

log "
  Что делать дальше:

  1. Если найдены SSH-ключи, которые вы не добавляли:
     → удалить немедленно, сменить пароль root

  2. Если ld.so.preload не пустой:
     → переходите в rescue-режим провайдера (Hetzner/DO/OVH)
     → все проверки с этого сервера бессмысленны

  3. Если найдены триггеры или UDF:
     → сделать дамп для форензики:
        mysqldump --all-databases > dump_forensic_$(date +%F).sql
     → сделать безопасный дамп для восстановления:
        mysqldump --all-databases --skip-triggers --routines=FALSE \\
          --no-create-info > dump_clean_$(date +%F).sql

  4. Если secure_file_priv пустой:
     → добавить в /etc/mysql/my.cnf:
        [mysqld]
        secure_file_priv = NULL

  5. WordPress: после зачистки обязательно перегенерировать SALT-ключи:
     → https://api.wordpress.org/secret-key/1.1/salt/
     → вставить в wp-config.php (сбрасывает все активные сессии)

  6. Сменить ВСЕ пароли: root, cPanel, FTP, БД, API-ключи

  7. Файлы веб-контента должны принадлежать веб-пользователю,
     НЕ пользователю mysql:
     chown -R www-data:www-data /var/www/html
     chmod -R 755 /var/www/html
"

log "\n  Отчёт сохранён: $REPORT"
log "  Канал по кибербезопасности: t.me/safebdv"
log "============================================================\n"
