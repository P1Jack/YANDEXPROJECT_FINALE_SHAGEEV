# YANDEXPROJECT_FINALE_SHAGEEV
Здравствуйте! В данном проекте я постарался сделать приближенный к настоящему менеджер паролей с криптостойким шифрованием паролей AES.
0. Вступительная информация о принципе работы приложения
  Для доступа к базе данных (хранилищу) требуется мастер ключ. В цедях безопастности, он нигде не хранится (ни в переменных, ни в файлах и т. д.). Возникает вопрос: 
  Как же программа проверяет введенный мастер ключ на соответствие? Давайте разбираться.
  При первом запуске программы она генерирует уникальную "соль" - набор из символов, который будет присоединен к зашифрованному ключу. Она записывается в 
  файл "config.txt". В дальнейшем она будет использоваться для проверки правильности мастер пароля с помощью функций encrypt и decrypt класса Encryptor. 
1. Первый запуск
  При первом запуске программа попросит пользователя ввести мастер ключ - "пароль от всех паролей". Удостоверьтесь в правильности пароля, запомните его. Именно
  его надо будет вводить при каждом запуске программы. Этот пароль можно будет поменять.
2. Главное окно
  В главном окне сразу бросается в глаза большой виджет - таблица. На нем показывается информация о всех паролях Вашего хранилища. При первом запуске она пустая,
  но это можно исправить, нажав кнопку "Добавить пароль". По ее нажатии появляется окно добавления пароля, в котором нужно ввести название секрета для 
  упрощения его поиска, логин от сайта, ссылку, сам пароль и заметки. Еще есть кнопка генерации надежного пароля, советую ей пользоваться, пароль генерируется 
  случайно и я гарантирую, что он не подведет. Далее надо нажать кнопку "Принять", и вуаля! Секрет с его данными появился на главном виджете.
  
  При долгой работе с менеджером паролей у пользователя скопится куча паролей, и при поиске конкретного пользователь сможет столкнуться со сложностями нахождения 
  нужного. Для этого в правом верхнем углу есть поле для ввода текста "Название или ключевое слово поиска". При вводе текста таблица обновляется, показывая 
  результаты поиска в реальном времени. Данная функция осуществляет поиск не только по названию, но и по логину, а также по URL.
  
  На любую ячейку таблицы можно кликнуть правой кнопкой мыши, появятся три кнопки: 
    "Копировать пароль":
      При нажатии пароль из выбранной ячейки таблицы копируется в буфер обмена. При этом происходит его декодинг из зашифрованного состояния в нормальное. 
    "Редактировать":
      При нажатии появляется окно, идентичное окну добавления пароля. Отличие лишь в том, что в поля для вводе уже введена информация из выбранной ячейки таблицы. 
      По окончании изменений нужно нажать кнопку "Принять".
    "Удалить":
      Тут все очевидно, секреты выбранной ячейки таблицы безвозвратно удаляются из базы данных.
  При нажатии левой кнопкой мыши по ячейке таблицы, на воле для вывода текста ниже виджета появится текст с информацией о выбранных секретах. Пароль выводиться 
  не будет, его можно скопировать, нажав ПКМ по полю вывода текста и нажав кнопку "Копировать пароль".
  В самом низу главного окна есть кнопка "Изменить мастер ключ". По ее нажатии открывается окно смены мастер ключа ("пароля от всех паролей"). 
  Программа попросит пользователя ввести старый мастер ключ, а затем новый дважды. При этом все существующие пароли перешифровываются для возможности 
  успешной расшифровки в будущем.
  