# Contributing

## Окружение

```sh
python3 -m pip install -e '.[dev]'
python3 -m pytest            # все тесты, включая e2e агента (нужны curl и openssl)
shellcheck -s sh agent/adf-agent.sh
```

## Правила

* Никаких заглушек и TODO вместо кода; каждая новая функция — с тестом.
* Синтаксис движков не смешивается. Новый параметр добавляется только со ссылкой на исходник или
  документацию движка (файл и строка) в `src/adf/data/methods.json` и/или докстринге модели.
* Возможности tachyon-core, известные только из CHANGELOG, помечаются `changelog` и должны
  проверяться через `adf caps` (`caps_test_matrix`).
* Утверждения о результатах — только по фактическим измерениям; результаты симулятора всегда
  помечаются как симуляция.
* Агент должен оставаться POSIX `sh` (busybox `ash`), без bash-измов; он не может менять firewall,
  маршрутизацию или конфигурацию роутера.
* В репозиторий не попадают пароли, ключи, токены, IP-адреса и конфигурации пользователей
  (`*.sqlite`, `*.bak`, `local/` в `.gitignore`).

## Новый движок

1. Класс `Engine` в `src/adf/engines/<name>.py`: `factors`, `check`, `render`, `parse`, `seeds`,
   `default_capabilities`.
2. Регистрация в `src/adf/engines/__init__.py`, грид скрининга в `generator.SCREENING`.
3. Тесты round-trip, валидации и известных неверных строк.
4. Если движок можно изолированно запустить на localhost (SOCKS) — поддержка в агенте и
   `AgentBackend.build_job`.
