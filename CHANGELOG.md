# Changelog

## Unreleased

* Импорт строит ровно тот `desync`-аутбаунд, который генерирует Tachyon (явные опции при
  `preset=auto`, значения по умолчанию ядра для отсутствующих опций вместо «выключено»).
* `adf tachyon-history`: разбор истории Fuzzer v2, найденные победители становятся кандидатами.
* `adf compare --current <секция>`: измерение текущей конфигурации как есть.
* `adf run` автоматически включает импортированные стратегии и победителей Fuzzer v2.
* Правила `seqovl` приведены к zapret/zapret2: ограничение «меньше первой позиции» только для
  disorder-режимов; nfqws2: рецепт `ts_up` и `seqovl_pattern`.
* Цели Instagram.
* Цель `youtube-video` указывает на `redirector.googlevideo.com`: `rr1.googlevideo.com` не
  существует (NXDOMAIN), и видео-цель всегда исключалась. Проверяется только TLS, не скорость потока.
* `adf import`, `adf compare --current`, `adf apply` различают desync-источники, которые не доходят
  до tachyon-core: секция с `action=desync` использует свои опции, а привязанный источник
  игнорирует. `import` не добавляет их в кандидаты, `apply` отказывается в них писать.
* `adf apply`: удаление отсутствующей опции больше не прерывает скрипт до `uci commit`.

## 0.1.0 — 2026-11-03

Первая версия.

* Аудит Tachyon DPI Fuzzer v2 / Native Desync, tachyon-core, zapret, zapret2, ByeDPI с
  ссылками на исходники (`docs/research/tachyon-fuzzer-audit.md`).
* База методов desync с синтаксисом и статусом поддержки по движкам (`src/adf/data/methods.json`).
* Модели движков: tachyon-core Native Desync (грамматика `connections.uc`, профили возможностей,
  проверка на бинарнике), zapret nfqws, zapret2 nfqws2, ByeDPI.
* Генератор: seeds, pairwise-план AETG, мутации, упрощения, случайная разведка.
* Поиск: Thompson sampling по Beta-апостериорным распределениям худшей цели, аддитивный суррогат,
  бим-поиск, исключение доминируемых, упрощение по не-худшести, финальная гонка на свежих данных.
* Оценка: интервал Уилсона, классы Not Working … Excellent, вердикты проб, отделение DPI от
  DNS/L4/сервера, контрольные цели, baseline.
* Обучение: SQLite, затухание, эпохи, детект дрейфа, переоценка прошлых победителей, память
  отвергнутых бинарником стратегий.
* OpenWrt-агент на POSIX sh: временный tachyon-core/ByeDPI на localhost, routing_mark,
  `--resolve` по IP CDN, IPv4/IPv6, stop-on-fail, `caps`, блокировка, контроль памяти.
* Интеграция с Tachyon: импорт секций (включая предупреждение об игнорируемом `desync_opts`),
  экспорт (UCI/desync_opts/JSON), apply с подтверждением и резервной копией, rollback.
* `adf compare` (Adaptive 2.0 / текущая / лучшая по кругу), `adf bench` (сравнение с эмуляцией
  Fuzzer v2 на симуляторе), отчёты Markdown.
