# FTDI/USB Logger 0.2.0

**захват J2534/USB-драйверов целиком, LAN-транспорт, живой снимок сессии**

Проверено на живом логе PCMflash + Scanmatik SM2 (чтение фулл-флеша MEDC17,
4 МБ): логируется весь обмен, который приложение реально сделало.

J2534 (PCMflash, Scanmatik, любой PassThru):
* хукаются ВСЕ экспорты PassThru*, включая PassThruConnect (его не было в логе
  вовсе) и PassThruReadVersion (версии DLL/FW/API);
* вендорные протоколы: `svc=0xNN` для протоколов без CAN-id (0x8003), ISO 14230
  разбирается по заголовку FMT/TGT/SRC — сервис больше не путается с FMT-байтом;
* пустые RX-сообщения (rxs=0x02, len=0) больше не считаются ответами: было 112
  ответов на 56 запросов, стало 56;
* ошибки PassThruReadMsgs/WriteMsgs и усечение пачки пишутся отдельными строками.

USB-драйверы (Scanmatik, WinUSB, HID):
* overlapped RX на USB-хендлах отдаётся в поток (ovlEmit + подметание
  Internal/InternalHigh) — bulk-обмен через ReadFile больше не теряется;
* DeviceIoControl учитывается в счётчиках хендла: `USB close` показывает bytes и
  ioctls, а не `bytes=0` при реальном трафике;
* чисто-выходные ioctl (без входного буфера) дампят ответ драйвера.

LAN (новый транспорт: DoIP, J2534-по-IP, ICOM/HSFZ):
* 11 хуков Winsock + WSASocketW/A и WSAConnect: CONNECT/TX/RX/CLOSE/ERR с
  local/remote, overlapped-WSARecv через WSAGetOverlappedResult и подметание;
* установка хуков идемпотентна по адресу (повторный dispatch модуля давал
  второй listener и дублировал каждую строку);
* закрытия сокетов без обмена (пробы сети, резолвер) свёрнуты в одну строку-
  счётчик вместо десятка `LAN CLOSE … local=? bytes=0`;
* движок: Transport::Lan, разбор DoIP (тип, source/target, UDS/NRC), подсказка
  протокола по портам (13400 DoIP, 6801 HSFZ/ICOM, 7777-7778 J2534-IP).

Сессия и отчёты:
* session.json обновляется каждые 2 с и учитывает ОТКРЫТЫЙ шаг — экспорт во
  время записи больше не отдаёт `steps: 0` при живом steps/NN.json;
* при экспорте снимается согласованный снимок: файл шага, отчёт и счётчики, не
  останавливая захват;
* транспорт сессии определяется по фактическим событиям (j2534, а не vcp).

Тесты: 120 passed, 0 failed. Регресс на живой лог PCMflash — engine/tests/pcmflash_j2534.rs
(на чистом клоне, где нет reference/logs, тест пропускается).
