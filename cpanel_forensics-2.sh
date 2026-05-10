#!/bin/bash
# ============================================================
# cpanel_forensics.sh — Форензика после CVE-2026-41940
# cPanel/WHM + MySQL/MariaDB
# Автор: Батранков Денис · t.me/safebdv
# Версия: 1.1 · Май 2026
#
# Запуск: sudo bash cpanel_forensics.sh
# Отчёт сохраняется в: /tmp/forensics_report_ДАТА.txt
#
# ВНИМАНИЕ: отчёт содержит чувствительные данные (SSH-ключи,
# имена пользователей, пути). Не публикуйте его открыто.
# ============================================================

# Оставляем только pipefail — -e и -u убраны намеренно:
# crontab -u $u -l возвращает ненулевой код на пустом crontab
# и убьёт скрипт с set -e. Ошибки обрабатываются вручную через || true.
set -o pipefail

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

# Директории для поиска файлов — намеренно ограничены.
# find / -mtime -75 на большом сервере может занять часы.
SEARCH_DIRS="/home /var/www /etc /root /tmp /var/tmp /usr/local"

# ── Вывод ────────────────────────────────────────────────────
log()  { echo -e "$1" | tee -a "$REPORT"; }
hdr()  { log "\n${BLD}${CYN}══════════════════════════════════════${RST}"; log "${BLD}${CYN}  $1${RST}"; log "${CYN}══════════════════════════════════════${RST}"; }
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

# ── Проверка Docker ───────────────────────────────────────────
if [[ -f /.dockerenv ]]; then
  echo -e "${YEL}⚠  Скрипт запущен внутри Docker-контейнера.${RST}"
  echo -e "${YEL}   Проверки systemd, /proc/*/exe и ld.so.preload могут работать некорректно.${RST}"
  echo -e "${YEL}   Продолжить? [y/N]${RST}"
  read -r ans
  [[ "$ans" =~ ^[Yy]$ ]] || exit 0
fi

log "============================================================"
log " ФОРЕНЗИКА cPanel/WHM · CVE-2026-41940 · $(date)"
log " Отчёт: $REPORT"
log " Период уязвимости: $VULN_START — $VULN_END"
log " Директории поиска: $SEARCH_DIRS"
log " ВНИМАНИЕ: отчёт содержит чувствительные данные."
log "============================================================"

# ════════════════════════════════════════════════════════════
# БЛОК 1: ФАЙЛОВАЯ СИСТЕМА И SSH
# ════════════════════════════════════════════════════════════

hdr "1/11 · SSH-КЛЮЧИ"

log "\n  [1a] authorized_keys у root:"
sep
if [[ -f /root/.ssh/authorized_keys ]]; then
  KEYS=$(wc -l < /root/.ssh/authorized_keys || echo 0)
  if [[ "$KEYS" -gt 0 ]]; then
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
while IFS=: read -r u _ uid _; do
  if [[ "$uid" -ge 1000 ]]; then
    f="/home/$u/.ssh/authorized_keys"
    if [[ -f "$f" ]]; then
      K=$(wc -l < "$f" || echo 0)
      warn "Пользователь $u: $K ключ(ей) в $f"
      cat "$f" 2>/dev/null | tee -a "$REPORT" | sed 's/^/    /'
    fi
  fi
done < /etc/passwd

# ────────────────────────────────────────────────────────────
hdr "2/11 · ПОЛЬЗОВАТЕЛИ С UID 0"

EXTRA_ROOT=$(awk -F: '($3==0 && $1!="root"){print $0}' /etc/passwd || true)
if [[ -n "$EXTRA_ROOT" ]]; then
  crit "Найдены пользователи с UID 0 кроме root:"
  echo "$EXTRA_ROOT" | tee -a "$REPORT" | sed 's/^/    /'
else
  ok "Только root имеет UID 0"
fi

log "\n  Последние 20 аккаунтов в /etc/passwd:"
sep
awk -F: '{print $1}' /etc/passwd | tail -20 | tee -a "$REPORT" | sed 's/^/    /'

# ────────────────────────────────────────────────────────────
hdr "3/11 · РУТКИТЫ: ld.so.preload"

if [[ -f /etc/ld.so.preload ]] && [[ -s /etc/ld.so.preload ]]; then
  crit "/etc/ld.so.preload НЕ ПУСТОЙ — вероятен руткит уровня ядра!"
  crit "Все утилиты (ps, ls, top, ss) на этом сервере могут врать."
  crit "Переходите в rescue-режим провайдера (Hetzner/DO/OVH)."
  cat /etc/ld.so.preload | tee -a "$REPORT" | sed 's/^/    /'
else
  ok "/etc/ld.so.preload пустой или отсутствует"
fi

# ────────────────────────────────────────────────────────────
hdr "4/11 · АЛИАСЫ, PATH И ПОДМЕНА КОМАНД"

log "\n  Текущие алиасы:"
sep
alias 2>/dev/null | tee -a "$REPORT" | sed 's/^/    /' || true

log "\n  Пути к системным утилитам (должны быть /bin или /usr/bin):"
sep
for cmd in ls ps top lsof ss; do
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
hdr "5/11 · АВТОЗАГРУЗКА (zsh/bash)"

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
hdr "6/11 · CRON"

log "\n  crontab root:"
sep
crontab -l 2>/dev/null | tee -a "$REPORT" | sed 's/^/    /' || info "crontab root пустой"

log "\n  /etc/crontab и /etc/cron.d/:"
sep
cat /etc/crontab 2>/dev/null | tee -a "$REPORT" | sed 's/^/    /' || true
ls -la /etc/cron.d/ 2>/dev/null | tee -a "$REPORT" | sed 's/^/    /' || true

log "\n  Cron всех пользователей:"
sep
while IFS=: read -r u _; do
  CTAB=$(crontab -u "$u" -l 2>/dev/null || true)
  if [[ -n "$CTAB" ]]; then
    warn "Пользователь $u имеет crontab:"
    echo "$CTAB" | tee -a "$REPORT" | sed 's/^/    /'
  fi
done < /etc/passwd

# ────────────────────────────────────────────────────────────
hdr "7/11 · SYSTEMD-ЮНИТЫ И ПРОЦЕССЫ"

log "\n  Все запущенные сервисы (проверьте незнакомые вручную):"
sep
systemctl list-units --type=service --state=running --no-pager 2>/dev/null \
  | tee -a "$REPORT" | sed 's/^/    /' || true

log "\n  Сервисы, добавленные за период уязвимости ($DAYS дней):"
sep
find /etc/systemd /lib/systemd -name "*.service" -mtime -"$DAYS" 2>/dev/null \
  | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "Свежих service-файлов не найдено"

log "\n  Процессы с удалённым бинарником (исключены стандартные lib):"
sep
ls -la /proc/*/exe 2>/dev/null \
  | grep deleted \
  | grep -vE "/(lib|ld-|vmlinux|systemd)" \
  | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "Процессов с нестандартным deleted-бинарником не найдено"

log "\n  Топ-10 процессов по CPU:"
sep
ps auxwwf 2>/dev/null | sort -rn -k3 | head -10 | tee -a "$REPORT" | sed 's/^/    /' || true

# ────────────────────────────────────────────────────────────
hdr "8/11 · СЕТЬ"

log "\n  Исходящие соединения (ESTABLISHED):"
sep
ss -tnp 2>/dev/null | grep ESTABLISHED | tee -a "$REPORT" | sed 's/^/    /' || true

log "\n  Открытые порты:"
sep
ss -tulpn 2>/dev/null | tee -a "$REPORT" | sed 's/^/    /' || true

log "\n  ELF-бинарники в /tmp и /dev/shm:"
sep
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null \
  | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "Исполняемых файлов в /tmp не найдено"

# ────────────────────────────────────────────────────────────
hdr "9/11 · ИСТОРИЯ КОМАНД"

for hfile in ~/.zsh_history ~/.bash_history /root/.bash_history /root/.zsh_history; do
  if [[ -f "$hfile" ]]; then
    HITS=$(grep -E "wget|curl|base64|python.*-c|perl.*-e|nc |ncat|/dev/tcp" "$hfile" 2>/dev/null || true)
    if [[ -n "$HITS" ]]; then
      warn "Подозрительные команды в $hfile:"
      echo "$HITS" | tee -a "$REPORT" | sed 's/^/    /'
    else
      ok "$hfile — подозрительных команд не найдено"
    fi
    info "Дата изменения $hfile: $(stat -c '%y' "$hfile" 2>/dev/null || true)"
  fi
done

# ────────────────────────────────────────────────────────────
hdr "10/11 · СВЕЖИЕ ФАЙЛЫ И ВЕБ-ШЕЛЛЫ"

log "\n  ВНИМАНИЕ: поиск ограничен $SEARCH_DIRS — для полного поиска"
log "  расширьте SEARCH_DIRS в начале скрипта."

log "\n  PHP-файлы новее /etc/passwd:"
sep
find $SEARCH_DIRS -name "*.php" -newer /etc/passwd 2>/dev/null \
  | grep -v "cache\|vendor\|node_modules" \
  | head -30 | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "Свежих PHP-файлов не найдено"

log "\n  PHP в uploads (там не должно быть .php):"
sep
find $SEARCH_DIRS -path "*/uploads/*.php" 2>/dev/null \
  | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "PHP в uploads не найден"

log "\n  Поиск веб-шеллов (eval, base64, rot13, gzinflate, preg_replace/e):"
sep
grep -rlE \
  "eval\s*\(\s*base64_decode|str_rot13|gzinflate\s*\(|preg_replace\s*\(.*\/e|assert\s*\(\s*\\\$" \
  $SEARCH_DIRS 2>/dev/null \
  | grep "\.php$" \
  | head -20 | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "Подозрительных PHP-конструкций не найдено"

log "\n  Файлы Sorry Ransomware (.sorry):"
sep
find $SEARCH_DIRS -name "*.sorry" 2>/dev/null \
  | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "Файлов .sorry не найдено"

# ────────────────────────────────────────────────────────────
hdr "11/11 · .SO БИБЛИОТЕКИ ВНЕ СТАНДАРТНЫХ ПУТЕЙ"

log "\n  .so файлы в /tmp /var/tmp /dev/shm (там им не место):"
sep
find /tmp /var/tmp /dev/shm -name "*.so" 2>/dev/null \
  | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "Не найдено"

log "\n  Загруженные .so по данным lsof (нестандартные пути):"
sep
lsof 2>/dev/null \
  | grep "\.so" \
  | grep -vE "/(lib|lib64|usr/lib|usr/lib64)/" \
  | tee -a "$REPORT" | sed 's/^/    /' \
  || ok "Нестандартных загруженных .so не найдено"

# ════════════════════════════════════════════════════════════
# БЛОК 2: MySQL / MariaDB
# ════════════════════════════════════════════════════════════

hdr "БЛОК MySQL"

if ! command -v mysql &>/dev/null; then
  warn "MySQL/MariaDB не найден — пропускаем блок БД"
else

run_sql() {
  local query="$1"
  mysql -N -e "$query" 2>/dev/null || warn "Ошибка SQL-запроса"
}

# ── M1. secure_file_priv ─────────────────────────────────────
log "\n${BLD}[M1] secure_file_priv — конфигурационный предохранитель:${RST}"
sep
SFP_RAW=$(mysql -N -e "SHOW VARIABLES LIKE 'secure_file_priv';" 2>/dev/null | awk '{print $2}')

# Три явных случая — не смешиваем -z и "NULL"
if [[ "$SFP_RAW" == "NULL" ]]; then
  ok "secure_file_priv = NULL — INTO OUTFILE полностью заблокирован"
elif [[ -z "$SFP_RAW" ]]; then
  crit "secure_file_priv = '' (пустая строка) — запись разрешена в ЛЮБУЮ директорию!"
  crit "Петля самовосстановления через INTO OUTFILE активна."
  crit "Исправить: добавьте в /etc/mysql/my.cnf → secure_file_priv = NULL"
else
  warn "secure_file_priv = '$SFP_RAW' — запись ограничена этим путём"
  info "Убедитесь что $SFP_RAW не содержит /home /var/www"
fi

# ── M2. init_connect и init_file ─────────────────────────────
log "\n${BLD}[M2] init_connect и init_file — выполнение при каждом подключении:${RST}"
sep
IC=$(run_sql "SHOW VARIABLES LIKE 'init_connect';" | awk '{print $2}')
IF=$(run_sql "SHOW VARIABLES LIKE 'init_file';" | awk '{print $2}')

if [[ -n "$IC" && "$IC" != "NULL" ]]; then
  crit "init_connect не пустой — SQL выполняется при каждом подключении:"
  echo "    $IC" | tee -a "$REPORT"
else
  ok "init_connect пустой"
fi

if [[ -n "$IF" && "$IF" != "NULL" ]]; then
  crit "init_file указывает на файл: $IF"
  info "Содержимое файла:"
  cat "$IF" 2>/dev/null | tee -a "$REPORT" | sed 's/^/    /' || warn "Файл недоступен"
else
  ok "init_file не задан"
fi

# ── M3. Плагины ─────────────────────────────────────────────
log "\n${BLD}[M3] Плагины MySQL (SHOW PLUGINS):${RST}"
sep
PLUGINS=$(run_sql "SELECT PLUGIN_NAME, PLUGIN_STATUS, PLUGIN_LIBRARY
  FROM information_schema.plugins
  WHERE PLUGIN_LIBRARY IS NOT NULL;")
if [[ -n "$PLUGINS" ]]; then
  info "Плагины с библиотеками — проверьте незнакомые:"
  echo "$PLUGINS" | tee -a "$REPORT" | sed 's/^/    /'
else
  ok "Нестандартных загруженных плагинов нет"
fi

# ── M4. plugin_dir и свежие .so ─────────────────────────────
log "\n${BLD}[M4] Директория плагинов и свежие .so:${RST}"
sep
PLUGIN_DIR=$(run_sql "SHOW VARIABLES LIKE 'plugin_dir';" | awk '{print $2}')
info "plugin_dir = $PLUGIN_DIR"
if [[ -n "$PLUGIN_DIR" && -d "$PLUGIN_DIR" ]]; then
  FRESH_SO=$(find "$PLUGIN_DIR" -name "*.so" -mtime -"$DAYS" 2>/dev/null)
  if [[ -n "$FRESH_SO" ]]; then
    crit "Свежие .so в plugin_dir (период уязвимости):"
    echo "$FRESH_SO" | tee -a "$REPORT" | sed 's/^/    /'
  else
    ok "Свежих .so в plugin_dir не найдено"
  fi
fi

# ── M5. UDF функции ──────────────────────────────────────────
log "\n${BLD}[M5] UDF-функции (mysql.func):${RST}"
sep
UDF=$(run_sql "SELECT name, dl FROM mysql.func;" 2>/dev/null)
if [[ -n "$UDF" ]]; then
  crit "Найдены UDF-функции:"
  echo "$UDF" | tee -a "$REPORT" | sed 's/^/    /'
else
  ok "mysql.func пустая — UDF не зарегистрированы"
fi

# ── M6. Триггеры ─────────────────────────────────────────────
log "\n${BLD}[M6] Триггеры вне системных схем:${RST}"
sep
TRIGGERS=$(run_sql "SELECT CONCAT(trigger_schema,'.',trigger_name,
  ' | TABLE: ',event_object_table,
  ' | ',LEFT(action_statement,80))
  FROM information_schema.triggers
  WHERE trigger_schema NOT IN ('mysql','sys','performance_schema');")
if [[ -n "$TRIGGERS" ]]; then
  crit "Найдены нестандартные триггеры:"
  echo "$TRIGGERS" | tee -a "$REPORT" | sed 's/^/    /'
else
  ok "Нестандартных триггеров не найдено"
fi

# ── M7. EVENT SCHEDULER ─────────────────────────────────────
log "\n${BLD}[M7] Планировщик событий (EVENT SCHEDULER):${RST}"
sep
ES=$(run_sql "SHOW VARIABLES LIKE 'event_scheduler';" | awk '{print $2}')
info "event_scheduler = $ES"
EVENTS=$(run_sql "SELECT event_schema, event_name, status, LEFT(event_definition,80)
  FROM information_schema.events
  WHERE event_schema NOT IN ('mysql','sys');")
if [[ -n "$EVENTS" ]]; then
  warn "Найдены пользовательские события:"
  echo "$EVENTS" | tee -a "$REPORT" | sed 's/^/    /'
else
  ok "Пользовательских событий не найдено"
fi

# ── M8. Хранимые процедуры ───────────────────────────────────
log "\n${BLD}[M8] Хранимые процедуры и функции:${RST}"
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

# ── M9. Опасные привилегии ───────────────────────────────────
log "\n${BLD}[M9] Опасные привилегии (FILE, SUPER, анонимные):${RST}"
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

# ── M10. Пользователи по дате ────────────────────────────────
log "\n${BLD}[M10] Пользователи MySQL по дате (ищем $VULN_START — $VULN_END):${RST}"
sep
MYSQL_VER=$(mysql -N -e "SELECT VERSION();" 2>/dev/null | head -1)
info "Версия: $MYSQL_VER"

HAS_COL=$(run_sql "SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema='mysql' AND table_name='user'
  AND column_name='password_last_changed';")

if [[ "${HAS_COL:-0}" -gt 0 ]]; then
  run_sql "SELECT user, host, password_last_changed
    FROM mysql.user ORDER BY password_last_changed DESC;" \
    | tee -a "$REPORT" | sed 's/^/    /'
  warn "Имена-маски хакеров: cpanel_backup, mysql_monitor, admin_support, service_account"
else
  warn "Столбец password_last_changed недоступен в этой версии"
  info "Альтернатива: дата изменения файлов в /var/lib/mysql/mysql/"
  find /var/lib/mysql/mysql -name "*.frm" -o -name "*.ibd" 2>/dev/null \
    | xargs ls -la 2>/dev/null \
    | grep -E "Feb|Mar|Apr" \
    | tee -a "$REPORT" | sed 's/^/    /' || true
fi

# ── M11. Бинарные логи ──────────────────────────────────────
log "\n${BLD}[M11] Бинарные логи:${RST}"
sep
LOG_BIN=$(run_sql "SHOW VARIABLES LIKE 'log_bin';" | awk '{print $2}')
if [[ "$LOG_BIN" == "ON" ]]; then
  info "Бинарные логи включены"
  run_sql "SHOW BINARY LOGS;" | tee -a "$REPORT" | sed 's/^/    /' || true
  BINLOG_PATH=$(run_sql "SHOW VARIABLES LIKE 'log_bin_basename';" | awk '{print $2}')
  info "Путь: $BINLOG_PATH"
  log ""
  info "Выполните вручную (логи могут быть большими):"
  log "    mysqlbinlog \\"
  log "      --start-datetime=\"$VULN_START 00:00:00\" \\"
  log "      --stop-datetime=\"$VULN_END 23:59:59\" \\"
  log "      ${BINLOG_PATH}.* \\"
  log "      | grep -i \"outfile\\|create user\\|grant\\|drop\""
else
  info "Бинарные логи выключены (log_bin=OFF)"
fi

# ── M12. Сетевая активность mysqld ──────────────────────────
log "\n${BLD}[M12] Сетевая активность mysqld:${RST}"
sep
MYSQL_NET=$(ss -tnp 2>/dev/null | grep mysqld | grep -v "127.0.0.1:3306" || true)
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

hdr "ИТОГ И СЛЕДУЮЩИЕ ШАГИ"

log "
  1. Нашли чужие SSH-ключи:
     → удалить, сменить пароль root с чистой машины

  2. ld.so.preload не пустой:
     → СТОП. Перейдите в rescue-режим провайдера.
        Все результаты этого скрипта ненадёжны.

  3. secure_file_priv пустой:
     → добавить в /etc/mysql/my.cnf:
        [mysqld]
        secure_file_priv = NULL

  4. Найдены триггеры или UDF:
     → сохранить форензик-дамп:
        mysqldump --all-databases > dump_forensic_$(date +%F).sql
     → безопасный дамп для восстановления:
        mysqldump --all-databases \\
          --skip-triggers --routines=FALSE --no-create-info \\
          > dump_clean_$(date +%F).sql

  5. WordPress — перегенерировать SALT-ключи:
     → https://api.wordpress.org/secret-key/1.1/salt/
     → вставить в wp-config.php
        (сбрасывает все активные сессии, включая хакерские)

  6. Права на папки веб-контента:
     → chown -R www-data:www-data /var/www/html
        (пользователь mysql не должен иметь write-доступ)

  7. Сменить ВСЕ пароли: root, cPanel, FTP, БД, API-ключи

  8. Если shared-хостинг:
     → требуйте письменный отчёт за февраль–апрель.
        Ответ «мы обновились» не считается.
"

log "  Отчёт сохранён: $REPORT"
log "  ${RED}Не публикуйте отчёт открыто — он содержит чувствительные данные.${RST}"
log "  Канал: t.me/safebdv"
log "============================================================"
