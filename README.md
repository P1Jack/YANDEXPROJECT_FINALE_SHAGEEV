# YANDEXPROJECT_P1QtPass
Определение значений: \
**База данных** = **Хранилище** - база данных с данными пользователей и их пароями. \
**Виджет - таблица** = **Таблица** - виджет на главном экране приложения, отоброжающий базу данных. \
**Мастер-ключ** = **Мастер пароль** - пароль от хранилища, по которому осуществляется открытие хранилища,
а также шифровка паролей. \
**Секрет** - данные (пароль, логин, url, заметки, название) из базы данных. \
**uid** = **уникальный идентификатор (ID)** - идентификатор, по которому осуществляется оперирование (поиск, редактирование и т. д.) с данными таблиц.

Здравствуйте! В данном проекте я постарался сделать приближенный к настоящему менеджер паролей с криптостойким шифрованием паролей с использованием алгоритма AES. 


0. **Вступительная информация о принципе работы приложения** \
  Для доступа к базе данных (хранилищу) требуется мастер ключ. В целях безопасности, он нигде не хранится (ни в переменных, ни в файлах и т. д.). Возникает вопрос: 
  Как же программа проверяет введенный мастер ключ на соответствие? Давайте разбираться.
  При первом запуске программы она генерирует уникальную "соль" - случайный набор из символов, который будет присоединен к зашифрованному ключу. Она записывается в 
  файл "config.txt". В дальнейшем она будет использоваться для проверки правильности мастер пароля с помощью методов encrypt и decrypt класса Encryptor. 
  Для хранения данных используется база данных sqlLite. Все пароли пользователя хранятся в ней в зашифрованном виде (зашифрованы мастер ключом). 
  Для шифрования используется алгоритм AES. Он является симметричным алгоритмом блочного шифрования и является стандартом шифрования для многих систем. 
  Помимо пароля в базе хранится вспомогательная информация, такая как: логин, ссылка на сервис, название и заметки, добавленные пользователем. В приложении возможен 
  удобный поиск по секретам, сохраненным в хранилище. Для защиты от визуального раскрытия пароля (злоумышленник подсомтрел пароль на экране) при расшифровке 
  пароль автоматически копируется в буфер обмена и не отображается внутри приложения. 
1. **Первый запуск** \
  При первом запуске программа попросит пользователя придумать и ввести мастер пароль - "пароль от всех паролей". Удостоверьтесь в правильности пароля, запомните его. Именно
  его надо будет вводить при каждом запуске программы для расшифровки базы с паролями. Этот мастер пароль можно будет поменять в главном меню приложения. Важно не удалять
  файл "config.txt", содержащий соль, так как в этом случае расшифровка базы будет невозможна. Также можно импортировать файл базы паролей, ранее экспортированный с другого
  устройства.
2. **Главное окно** \
  В главном окне сразу бросается в глаза большой виджет - таблица. На нем отображается информация о всех паролях Вашего хранилища. При первом запуске она пустая,
  но это можно исправить, нажав кнопку "Добавить пароль". При ее нажатии появляется окно добавления пароля, в котором нужно ввести название секрета для 
  упрощения его поиска, логин от сайта, ссылку, сам пароль и заметки. Еще есть кнопка автогенерации пароля, которой рекомендовано пользоваться, пароль генерируется 
  случайно и гарантируется, что он будет надежным, потому что важно, чтобы пароли для всех сервисов были различны. Пароли по умолчанию отображаются скрытыми символами 
  (в данном случае классическими кружочками), есть кнопка "Показать пароль", чтобы посмотреть, не была ли совершена ошибка при вводе.
  Далее надо нажать кнопку "Принять", и вуаля! И новый секрет сразу появился на главном виджете.
  
  При долгой работе с приложением у пользователя появится много паролей, и при поиске конкретного секрета он может столкнуться со сложностями нахождения.
  Для этого в правом верхнем углу есть поле для ввода текста "Название или ключевое слово поиска". При вводе текста таблица обновляется, показывая 
  результаты фильтрации секретов по введенной строке. Данная функция осуществляет поиск не только по названию, но и по логину, а также по URL.
  
  На любую ячейку таблицы можно кликнуть правой кнопкой мыши, появятся три кнопки: 
    "Копировать пароль":
      При нажатии пароль из выбранной ячейки таблицы копируется в буфер обмена. При этом происходит его преобразование из зашифрованного вида в нормальное. 
    "Редактировать":
      При нажатии появляется окно, идентичное окну добавления пароля. Отличие лишь в том, что в поля для вводе уже введена информация из выбранной ячейки таблицы. 
      По окончании изменений нужно нажать кнопку "Принять" чтобы обновить данные этого секрета.
    "Удалить":
      Секрет из выбранной строки таблицы безвозвратно удаляется из базы данных.
  При нажатии левой кнопкой мыши по ячейке таблицы, на поле для вывода текста ниже виджета-таблицы появится текст с информацией о выбранном секрете. Пароль отображаться
  не будет, его можно скопировать, нажав ПКМ по полю вывода текста и нажав кнопку "Копировать пароль".

  В самом низу главного окна есть кнопка "Изменить мастер ключ". При ее нажатии открывается окно смены мастер ключа ("пароля от всех паролей"). 
  Программа попросит пользователя ввести старый мастер ключ, а затем новый дважды. При этом все существующие пароли перешифровываются для возможности 
  успешной расшифровки в будущем.
