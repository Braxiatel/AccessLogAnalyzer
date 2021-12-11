Mini Log Analyzer
_________________

Небольшой скрипт для обработки NGINX access логов. При запуске скрипт обрабатывает последний лог в ``LOG_DIR``. 
В результате анализа скрипт выводит статистику по данному лог файлу в html репорт в папку ``REPORT_DIR``. 
В статистике отображены:
- **count** - сĸольĸо раз встречается URL, абсолютное значение
- **count_perc** - сĸольĸо раз встречается URL, в процентнах относительно общего числа запросов
- **time_sum** - суммарный $request_time для данного URL'а, абсолютное значение
- **time_perc** - суммарный $request_time для данного URL'а, в процентах относительно общего $request_time всех запросов
- **time_avg** - средний $request_time для данного URL'а
- **time_max** - маĸсимальный $request_time для данного URL'а
- **time_med** - медиана $request_time для данного URL'а
За объём данных в отчёте отвечает переменная ``REPORT_SIZE`` - в отчёт попадает указанное количество URL'ов 
с наибольшим суммарным временем обработĸи **time_sum**
  

Запуск скрипта
______________

Для запуска скрипта необходим python 3.9 и выше. Сторонних библиотек не требуется. Скрипту можно передать свой файл 
конфигураций, желательно в формате json. В файле конфигурации можно указывать следующие параметры:
"REPORT_SIZE": Ограничение объёма данных в отчёте.
"REPORT_DIR": Папка, куда скрипт будет складывать отчёты,
"LOG_DIR": Папка, где скрипт будет искать логи,
"LOG_FILE": Файл куда буду писаться логи в процессе работы скрипта. Дефолтное значение None, логи пишутся в stdout.

Путь к конфигу можно передавать скрипту через параметр --config или -с. Пример запуска скрипта:

$python log_analyzer --config ./config.json


Запуск тестов
_____________
Для скрипта написаны юнит тесты с помощью библиотеки unittest. В папке tests находятся файлы и директории необходимые 
для тестирования, сами тесты находятся в test_log_analyzer.py. Пример запуска тестов:

python -m unittest
