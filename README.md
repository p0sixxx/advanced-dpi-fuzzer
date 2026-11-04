# Advanced DPI Fuzzer (ADF)

Интеллектуальный подбор, измерение и оптимизация стратегий DPI desynchronization для
**Tachyon Native Desync (tachyon-core)** и **ByeDPI**, с моделями синтаксиса **zapret (nfqws)** и
**zapret2 (nfqws2)**. Цель — найти не просто «какую-то работающую», а **самую простую стратегию,
статистически надёжную на всех ваших ресурсах**, для конкретного провайдера и маршрута.

> Статус: 0.1.0. Код, тесты и агент проверены в CI-окружении (Linux, `dash` и busybox `ash`) и
> в реальных прогонах на GL.iNet Flint 2 (tachyon-core 0.3.4) — см. «Ограничения».

## Чем отличается от встроенного DPI Fuzzer v2 Tachyon

Подробный аудит с номерами строк исходников: [docs/research/tachyon-fuzzer-audit.md](docs/research/tachyon-fuzzer-audit.md).

| | Tachyon Fuzzer v2 | ADF |
|---|---|---|
| Пространство Native Desync | 6 режимов × 4 позиции × TTL × SNI; **fooling не перебирается**; `multi_*`, маркеры `sniext+1/host+1/endhost-1/extlen`, списки позиций отвергаются валидатором | все 9 режимов, 11 fooling, 20 позиций/списков, `seqovl/syndata/wsize/ipfrag/tlsrec_first`, UDP-параметры при наличии QUIC-целей; неизвестные бинарнику ключи отсекает `adf caps`, значения проверяются измерениями |
| Дубликаты | 282 кандидата, из них 138 уникальных (disorder/fake игнорируют часть параметров) | канонизация: эквивалентные конфигурации имеют один ID |
| Отбор | 1 проба на стратегию, 3 повтора для топ-5 | Thompson sampling по Beta-апостериорным распределениям + суррогатная модель + pairwise-план + локальный поиск |
| Решение «стабильно» | 3/3 = 100 % | нижняя граница 95 % интервала Уилсона по **худшей** обязательной цели, свежая (holdout) выборка в финале |
| Сеть упала | стратегии помечаются нерабочими | контрольные цели; пробы после последнего успешного контроля аннулируются, back-off |
| Обучение | лучший результат прошлых прогонов | все испытания в SQLite, затухание по времени, эпохи, детект дрейфа, переоценка старых победителей |
| Упрощение | нет | non-inferiority-гонка более простых вариантов |
| Синтаксис других движков | `fooling=` в nfqws2 (no-op), `badack` в nfqws1, `--auto=t,r,a,s` в ByeDPI | грамматика каждого движка по его исходникам; такие строки отвергаются с объяснением |

Результат на симуляторе (`adf bench`, 8 сидов, одинаковый бюджет ≈ 620 запросов): средняя истинная
надёжность выбранной стратегии **0.94** у ADF против **0.77** у эмуляции Fuzzer v2.
Это сравнение эффективности *алгоритма поиска* на синтетическом цензоре, а не результат в реальной
сети; реальное сравнение — команда `adf compare` (см. ниже).

## Архитектура

```
 ПК / сервер (контроллер, Python ≥ 3.11, без зависимостей)        Роутер OpenWrt (агент, POSIX sh + curl)
 ┌──────────────────────────────────────────────────────┐  SSH  ┌──────────────────────────────────────────┐
 │ engines/   грамматики tachyon-core, nfqws, nfqws2,     │──────▶│ adf-agent.sh                             │
 │            ByeDPI; канонизация; ограничения           │ job   │  • временный tachyon-core run -c cfg      │
 │ generator  seeds + pairwise (AETG) + мутации          │◀──────│    mixed-инбаунд 127.0.0.1, routing_mark  │
 │ search/    Thompson sampling, бим-поиск, упрощение,    │ JSON  │  • curl через SOCKS, --resolve по IP CDN  │
 │            финальная гонка на свежих данных           │ lines │  • ничего не меняет в firewall/UCI        │
 │ learning   суррогат, затухание, эпохи, дрейф          │       └──────────────────────────────────────────┘
 │ scoring    Wilson LB по худшей цели, классы           │
 │ db         SQLite: стратегии, испытания, эпохи,       │
 │            возможности бинарника, экспорты            │
 │ integrations/tachyon  импорт UCI, экспорт, apply,     │
 │            rollback                                   │
 └──────────────────────────────────────────────────────┘
```

Почему так: на Flint 2 (Cortex-A53, 1 ГБ) интерпретатор и ML-логика не нужны — агент занимает
единицы килобайт и запускает один временный `tachyon-core` за раз. Вся статистика и поиск — на ПК.
Контроллер может работать и на самом роутере (`--local`), если там установлен `python3`.
Подробнее: [docs/architecture.md](docs/architecture.md), агент: [docs/openwrt-agent.md](docs/openwrt-agent.md).

## Быстрый старт

```sh
git clone https://github.com/p0sixxx/advanced-dpi-fuzzer && cd advanced-dpi-fuzzer
python3 -m pip install -e .          # Python ≥ 3.11, без внешних зависимостей

adf bench                            # офлайн-проверка алгоритмов на симуляторе
adf validate "mode=fake_split split_pos=1 fake_ttl=6 fake_sni=max.ru repeats=6"
adf run --simulate                   # полный конвейер без сети
```

Работа с роутером (нужен SSH-доступ по ключу; пароль программа не запрашивает и не хранит):

```sh
adf env  --ssh root@192.168.8.1      # что установлено на роутере (агент копируется в /tmp)
adf caps --ssh root@192.168.8.1      # какие параметры desync принимает ваш tachyon-core
adf import --ssh root@192.168.8.1    # текущие секции Native Desync и предупреждения
adf tachyon-history --ssh root@192.168.8.1   # разбор истории Fuzzer v2, победители → кандидаты
adf run  --ssh root@192.168.8.1 --categories youtube,discord --network-id my-isp --report run.md
adf best --network-id my-isp
adf compare --ssh root@192.168.8.1 --network-id my-isp --best --current YouTube_desync --reps 30
adf apply --ssh root@192.168.8.1 --section <секция> <strategy-id> --dry-run   # показать изменения
adf apply --ssh root@192.168.8.1 --section <секция> <strategy-id>             # с подтверждением
adf rollback --ssh root@192.168.8.1 --section <секция>
```

`adf run` **ничего не меняет на роутере**: все пробы идут через временный `tachyon-core`
на `127.0.0.1`, исходящий трафик помечается меткой обхода Tachyon `0x08000000`; firewall,
nftables, маршрутизация и UCI не трогаются. Конфигурацию меняет только `adf apply` после явного
подтверждения (ввод имени секции), с полной резервной копией `uci export` на роутере и
посекционной копией в базе (`adf rollback`).

Остановка: `Ctrl+C`, `adf stop` или файл `~/.adf/STOP` — текущий пакет проб завершается, всё
сохраняется, следующий запуск продолжает с накопленными данными.

## Запуск на самом роутере

ПК нужен только для сборки: поиск работает на роутере в фоне и не зависит от SSH-сессии.
Сборка, на ПК (нужен только Python, файл появится в `dist/`):

```sh
python packaging/build_release.py
```

Установка, из Git Bash, WSL или Linux (PowerShell не поддерживает `<`):

```sh
ssh root@192.168.8.1 "cat > /tmp/adf-router.sh" < dist/adf-router-0.1.0.sh
ssh -t root@192.168.8.1 sh /tmp/adf-router.sh
```

Установщик ставит Python через `apk` или `opkg` (флаг `--no-deps` запрещает это) и разворачивает ADF
в `/opt/adf`. Tachyon, firewall и маршруты он не меняет. Повторный запуск обновляет ADF, не трогая
настройки в `/etc/adf/config.toml` и результаты в `/root/.adf`. Дальше команды выполняются на роутере:

```sh
adf-router run                                    # youtube,discord, до 60 минут, в фоне
adf-router run --categories discord --minutes 30
adf-router status                                 # идёт ли поиск и последние строки лога
adf-router log -f
adf-router stop                                   # данные сохраняются
adf-router report                                 # последний отчёт
adf-router best
adf-router uninstall                              # --purge удалит и результаты
```

`adf` на роутере работает как обычно: `adf import`, `adf compare ...`, `adf apply ...`. Конфигурацию
Tachyon меняет только `adf apply`, и только после подтверждения. База на роутере своя, результаты с
ПК в неё не попадают.

## Как Tachyon читает настройки Native Desync

Сверено с кодом Tachyon и с `/etc/tachyon-core/config.json` на роутере:

* `desync_opts` («Строка стратегии (Fuzzer / CLI)») читается **только** при пресете
  «Пользовательские параметры» (`connections.uc:1678,1734`). При Adaptive 2.0 (`preset=auto`) поле
  игнорируется, а явные опции ядро получает как стартовые значения.
* Секция с `action=desync` строит аутбаунд из **своих** опций `desync_*`. Источник (`outbound_source`),
  привязанный через `outbound_source_refs`, на него не влияет, даже если задаёт опции, которых в
  секции нет. `adf import` помечает такие источники как `inactive`, а `adf apply` в них не пишет.
* curl на роутере без HTTP/3, поэтому QUIC/UDP-параметры измерить нельзя (ADF их не трогает).

`adf compare --current <секция>` измеряет секцию ровно так, как её запускает Tachyon;
`adf apply` выставляет `desync_preset=custom`, `desync_auto_tune=0` и все параметры стратегии,
удаляя устаревшие. Проверяйте результат в `/etc/tachyon-core/config.json`, а не только в UCI.

## Цели и оценка

Цели — `src/adf/probe/targets.py` или свой TOML (`examples/targets.toml`): Google, YouTube,
YouTube Music, googlevideo, Discord, Telegram, GitHub, Cloudflare (+ контрольные `ya.ru`, `vk.com`).
Для каждой цели проверяются HTTP-статус, сертификат, **объём ответа** (обрыв ТСПУ на 16–20 КБ
виден только на больших ответах), содержимое (regex), до `max_ips` адресов CDN и IPv4/IPv6.

Классы: **Not Working / Unstable / Partially Working / Working / Stable / Excellent** — по нижней
границе интервала Уилсона худшей цели (`Working`: LB ≥ 0.50, n ≥ 5; `Stable`: LB ≥ 0.75, n ≥ 12;
`Excellent`: LB ≥ 0.85, n ≥ 30 и p90 TTFB не хуже 1.5× эталона).

## Ограничения (честно)

* Публичные исходники tachyon-core старее бинарника; поддержка `fooling`, `multi_*`, `seqovl` и т. п.
  взята из CHANGELOG/UI Tachyon. `tachyon-core check` 0.3.4 проверяет имена ключей, но не значения,
  поэтому `adf caps` не доказывает поддержку значения: её показывают только измерения.
  `adf caps` выводит такие ключи в `unverifiable_by_check`.
* `adf compare` перезапускает движок каждый раунд, поэтому Adaptive 2.0 измеряется с холодного старта.
* Цель `youtube-video` проверяет прохождение TLS к googlevideo, а не скорость видеопотока.
* `adf run` и `adf compare` без терминала (скрипты, агенты) требуют `--yes`.
* Установщик для роутера (`dist/adf-router-*.sh`) проверен тестами на имитации роутера (`sh`, busybox
  `ash`, поддельный `apk`), но ещё не устанавливался на настоящий OpenWrt.
* Тесты рассчитаны на Linux: на Windows запускайте их в WSL (e2e-тесты агента там не работают).
* zapret/zapret2: генерация, валидация и экспорт есть; прямое измерение через `adf-agent run` — нет
  (nfqws требует правил nfqueue). Агент умеет делегировать одну пробу встроенному фаззеру Tachyon
  (`adf-agent tachyon-probe`), но это меняет nft-таблицу Tachyon и вызывается только явно.
* UDP/QUIC оцениваются только при curl с HTTP/3 на роутере (`adf env` показывает `http3`).
* Симулятор (`adf bench`, `--simulate`) — синтетическая модель для проверки алгоритмов; его цифры
  не переносятся на реальную сеть.

## Документация

* [Аудит Tachyon Fuzzer v2 / Native Desync](docs/research/tachyon-fuzzer-audit.md)
* [База методов](src/adf/data/methods.json) (`adf methods`)
* [Архитектура и алгоритмы](docs/architecture.md)
* [OpenWrt-агент и протокол](docs/openwrt-agent.md)
* [CHANGELOG](CHANGELOG.md), [CONTRIBUTING](CONTRIBUTING.md)

## Лицензия

Лицензия проекта ещё не выбрана (будет добавлена после согласования с владельцем репозитория).
Код сторонних проектов не копировался: zapret/zapret2/ByeDPI (MIT) и Tachyon (GPL-2.0) изучались
как источники; tachyon-core распространяется под проприетарной лицензией и используется только как
внешний бинарник на роутере пользователя.
