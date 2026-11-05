# OpenWrt-агент (`agent/adf-agent.sh`)

POSIX `sh` (busybox `ash`), зависимости: `curl`, `awk`, `sed`, `grep`, `nslookup` — всё есть в
OpenWrt. Проверяется в CI под `dash` и busybox `ash`, `shellcheck -s sh`.

Контроллер копирует агент в `/tmp/adf-agent.sh` (tmpfs — после перезагрузки следов нет) и вызывает
его по SSH с `BatchMode=yes` (только ключи). Состояние — `/tmp/adf-agent` (права 700).

## Что агент делает и чего не делает

* Запускает **временный** `tachyon-core run -c /tmp/adf-agent/cfg.json` с `mixed`-инбаундом на
  `127.0.0.1:<port>` и одним аутбаундом (`desync` со стратегией или `direct` для baseline), предварительно
  выполнив `tachyon-core check`. Либо `ciadpi -i 127.0.0.1 -p <port> <args>` для ByeDPI.
* Аутбаунду задаётся `routing_mark` (по умолчанию `0x08000000` — метка, которую таблица Tachyon
  пропускает мимо TProxy), поэтому пробы идут напрямую через WAN.
* Делает `curl` через SOCKS, при наличии IP — `--resolve host:port:ip` (DNS исключён из измерения,
  проверяется каждый IP CDN), `-4/-6`, `-r` для потоковых целей, проверку содержимого `grep -E`.
* **Не изменяет** firewall, nftables, маршруты, UCI, Tachyon. Исключение — команда
  `tachyon-probe`, которая вызывает встроенный фаззер Tachyon (он сам создаёт свою nft-таблицу
  `tachyon_fuzzer`); контроллер не вызывает её автоматически.
* Отказывается работать при `MemAvailable < ADF_MIN_MEM_KB` (24 МБ), один экземпляр за раз
  (`mkdir`-блокировка), `trap` убивает временное ядро при любом выходе.

## Протокол задания (`adf-agent run`, stdin)

```
ADF-JOB 1
port 11290
reps 3
interval_ms 250
timeout 8
connect_timeout 4
stop_on_fail 0
engine tachyon | byedpi | none
config-begin
{ ... полный JSON-конфиг tachyon-core ... }
config-end
byedpi_args -s 1 -r 1+s
target <id> <ipv4|ipv6> <url> <ip|-> <min_bytes> <range|-> <https|streaming|quic> <regex|->
end
```

Вывод — JSON-строки: `{"t":"engine",...}`, `{"t":"probe","target":..,"code":..,"exit":..,"tc":..,
"ta":..,"tf":..,"tt":..,"size":..,"speed":..,"content":..}`, `{"t":"done","ok":true}`.

## Другие команды

* `env` — архитектура, версия OpenWrt, путь и версия `tachyon-core`, ByeDPI, curl и поддержка HTTP/3,
  память, загрузка.
* `resolve <host> [dns]` — адреса A/AAAA.
* `live-dns` — описание основного DNS-сервера и его bootstrap из конфига живого ядра. Читаются только эти
  два объекта, остальной конфиг с учётными данными прокси агент не выводит.
* `caps` — для каждой строки `ключ<TAB>значение<TAB>конфиг` выполняет `tachyon-core check`:
  так определяется, какие параметры desync понимает **ваш** бинарник.
* `stop` — убить временное ядро и снять блокировку.

## Переменные окружения

`ADF_STATE`, `ADF_CORE`, `ADF_CORE_CONFIG`, `ADF_BYEDPI`, `ADF_MIN_MEM_KB`, `ADF_CURL`.

## Файлы на ПК

`~/.adf` (или `ADF_HOME`): `config.toml` пишет `adf setup`, `check.json` хранит состояние идущей проверки,
`check.log` содержит вывод её процесса, `reports/` содержит отчёты, `adf.sqlite` содержит результаты.

## Нагрузка

Один временный процесс ядра, последовательные запросы с паузой ≥ 250 мс, пакеты не чаще 1 в
секунду (настраивается в контроллере). Нагрузочного тестирования внешних серверов нет: на цель —
единицы запросов в минуту.
