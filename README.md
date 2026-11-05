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

Одна команда в SSH роутера ставит всё необходимое и запускает проверку:

```sh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/p0sixxx/advanced-dpi-fuzzer/main/install.sh)"
```

Команда скачивает ADF с GitHub, ставит Python через `apk` или `opkg`, разворачивает всё в `/opt/adf`,
спрашивает сервис и длительность проверки (5, 20 или 60 минут) и в конце показывает отчёт. Tachyon,
firewall и маршруты она не меняет. Повторный запуск обновляет ADF и не трогает настройки
в `/etc/adf/config.toml` и результаты в `/root/.adf`.

Поиск идёт в фоне: Ctrl+C и обрыв SSH его не останавливают, ход и результат доступны в `adf-router`.

Перед установкой проверяется флеш: нужно 3 МБ и ещё 20 МБ, если нет Python (`--force` отключает
проверку). Если доступно меньше 96 МБ памяти, ADF предупредит. На слабых роутерах удобнее запускать ADF с
ПК по SSH: Python там не нужен. Если движок не успевает стартовать, увеличьте `[probe] engine_start_s`.

```sh
adf-router check                                  # проверка с выбором сервиса
adf-router check youtube --minutes 5              # без вопросов
adf-router status                                 # идёт ли поиск и последние строки лога
adf-router log -f
adf-router stop                                   # данные сохраняются
adf-router report                                 # последний отчёт
adf-router best                                   # лучшие стратегии с id
adf-router uninstall                              # --purge удалит и результаты
```

`adf` на роутере работает как обычно: `adf import`, `adf compare ...`, `adf apply ...`. Конфигурацию
Tachyon меняет только `adf apply`, и только после подтверждения. База на роутере своя, результаты с
ПК в неё не попадают.

Без доступа к GitHub установщик можно собрать на ПК и скопировать на роутер (Git Bash, WSL или Linux):

```sh
python packaging/build_release.py
ssh root@192.168.8.1 "cat > /tmp/adf-router.sh" < dist/adf-router-0.1.0.sh
ssh -t root@192.168.8.1 sh /tmp/adf-router.sh
```

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

Цели — `src/adf/probe/targets.py` или свой TOML (`examples/targets.toml`), контрольные — `ya.ru` и
`vk.com`. Хосты выбраны по спискам доменов, которые Tachyon использует для маршрутизации, и проверены
запросами. Обязательные цели определяют оценку, остальные видны в отчёте по целям:

| Сервис | Обязательные | Дополнительные |
|---|---|---|
| YouTube | `www.youtube.com`, `redirector.googlevideo.com`, `youtubei.googleapis.com` (приложения Android и iOS) | `i.ytimg.com`, `jnn-pa.googleapis.com`, `yt3.ggpht.com` |
| YouTube Music | `music.youtube.com` | |
| Discord | `discord.com`, `gateway.discord.gg`, `cdn.discordapp.com` | `media.discordapp.net`, `updates.discord.com` |
| Instagram | `www.instagram.com`, `i.instagram.com` (приложения) | `static.cdninstagram.com`, `scontent.cdninstagram.com`, `edge-chat.instagram.com` |
| Telegram | `web.telegram.org` | `api.telegram.org`, `t.me` |
| Google | `www.google.com` | `accounts.google.com`, `play.googleapis.com`, `fcm.googleapis.com` |
| GitHub | `github.com` | `api.github.com`, `raw.githubusercontent.com` |
| Cloudflare | `speed.cloudflare.com` | `www.cloudflare.com` |

Для каждой цели проверяются HTTP-статус, сертификат, **объём ответа** (обрыв ТСПУ на 16–20 КБ
виден только на больших ответах), содержимое (regex), до `max_ips` адресов CDN и IPv4/IPv6.

**Адреса и проверка DNS.** Клиенты за Tachyon получают FakeIP, а ядро само идёт на адрес, который вернул его
DNS. Другой сервер может вернуть другой адрес той же CDN, и стратегия может работать на одном и не работать на
другом: на Flint 2 AliDNS отдавал для `redirector.googlevideo.com` адрес, который не проходил ни с одной
проверенной стратегией, а Яндекс и Google отдавали рабочий. Поэтому адреса целей разрешает временное ядро через
DNS-сервер из конфига живого ядра, какого бы типа он ни был. Рядом работает независимый сервер сверки: Google,
а если ядро само использует Google, то Яндекс. Там, где сети адресов разошлись, лучшая стратегия проверяется
на обоих наборах, и раздел «Проверка DNS» в отчёте называет виновника. `[probe] dns_server` с адресом отключает
это и использует указанный сервер, `[probe] dns_check = false` отключает только сверку.

**Большое приветствие.** `curl` на роутере отправляет маленький ClientHello, а Chrome отправляет
1,9–2 КБ с постквантовым ключом и случайным порядком расширений. Стратегия может пройти все пробы `curl`
и зависать в Chrome: `fake_disorder split_pos=host+1` дал 150/150 с `curl` и 0/16 с настоящими
приветствиями Chrome. Поэтому для каждой обязательной HTTPS-цели добавляется цель `<id>-large`: контроллер
собирает такое приветствие сам (`src/adf/probe/hello.py`) и отправляет его одной записью через временный
движок, а успехом считается `ServerHello` от сервера. С ПК соединение идёт через `ssh -W`, на роутере
напрямую. Отключить можно через `[probe] large_hello = false`.

Пример, YouTube на Flint 2, ядро 0.3.4, по 10 кругов, успешные попытки:

| Стратегия | `curl`, обязательные цели | большое приветствие |
|---|---:|---:|
| `multi_disorder split_pos=1,sniext+1,midsld` | 40/40 | 31/40 |
| `fake_disorder split_pos=1` | 39/40 | 30/40 |
| `fake_disorder split_pos=host+1` | 40/40 | 8/40 |
| Adaptive 2.0 | 30/40 | 16/40 |

По `curl` первые три строки почти неотличимы, а по большому приветствию видно, почему `host+1` зависал в
Chrome. Adaptive 2.0 здесь не проходит `youtubei.googleapis.com`, поэтому он сломал бы мобильные приложения.

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
* Проба большого приветствия откалибрована по настоящим приветствиям Chrome, снятым локально
  (`docs/research/tachyon-fuzzer-audit.md`, раздел 2.11), но это проба, а не браузер: она проверяет только
  ответ сервера на приветствие. Для неё нужен разрешённый проброс TCP в SSH-сервере роутера: на dropbear
  Flint 2 он работает, а если его нет, поиск остановится с понятной ошибкой.
* Сверка DNS отвечает на вопрос, виноват ли адрес, только там, где независимый сервер вернул другую сеть. Если
  оба сервера отдают один и тот же нерабочий адрес, сверка этого не покажет. Запросы идут напрямую, даже если
  живой DNS настроен через секцию: тогда отчёт об этом предупреждает.
* Приложения Android и iOS представлены своим API (`youtubei.googleapis.com`, `i.instagram.com`), но их
  собственные TLS-приветствия не воспроизводятся. Протокол MTProto в Telegram проверить нельзя: цели
  Telegram показывают только веб-хосты.
* Результат относится к конкретной версии ядра. Смена `tachyon-core` начинает новую эпоху, но уже
  применённую стратегию заново не измеряет: после обновления запускайте `adf compare`.
* `adf run` и `adf compare` без терминала (скрипты, агенты) требуют `--yes`.
* Установка на роутер (`install.sh`, `dist/adf-router-*.sh`) проверена тестами на имитации роутера
  (`sh`, busybox `ash`, поддельные `apk` и `curl`), но ещё не запускалась на настоящем OpenWrt.
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
