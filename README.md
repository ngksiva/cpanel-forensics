# Форензика cPanel/WHM после CVE-2026-41940

Bash-скрипт для проверки сервера после уязвимости CVE-2026-41940 (CVSS 9.8).
64 дня атакующие имели root-доступ без пароля — патч не удаляет то, что уже занесли внутрь.

## Запуск

```bash
sudo bash cpanel_forensics.sh
```

Отчёт сохраняется в `/tmp/forensics_report_ДАТА.txt`

## Что проверяет

- SSH authorized_keys у всех пользователей
- Пользователи с UID 0
- Руткиты через ld.so.preload
- Алиасы, PATH, подмена команд
- Автозагрузка zsh/bash
- Cron, systemd-юниты
- Сетевая активность, процессы с deleted бинарником
- Веб-шеллы, файлы .sorry
- MySQL: secure_file_priv, plugin_dir, UDF, триггеры, привилегии, бинарные логи

Канал по кибербезопасности: [t.me/safebdv](https://t.me/safebdv)
