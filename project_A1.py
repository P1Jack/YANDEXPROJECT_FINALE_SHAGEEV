import os
import sqlite3
import sys
import traceback
from pyperclip import copy
from ui_project_login import Ui_LogWindow
from pass_add import Ui_addPassDialog
from ui_project_main import Ui_MainWindow
from master_change import Ui_MasterChange
from p1qtpass_main import add_password, get_random_salt, check_valid_master_key, launch_p1qtpass, edit_password, \
    runtime_ctx, Encryptor, create_validation_key, Config, create_config, get_all_passwords, refresh_all_passwords
from PyQt5 import QtCore
from PyQt5.QtWidgets import QMainWindow, QTableWidgetItem, QLineEdit, QMenu
from PyQt5 import QtWidgets


# Определение значений:
# База данных = Хранилище - база данных с данными пользователей и их пароями.
# Виджет = Таблица - виджет на главном экране приложения, отоброжающий базу данных.
# Мастер-ключ = Мастер пароль - пароль от хранилища, по которому осуществляется открытие хранилища,
# а также шифровка паролей.
# Секрет - данные (пароль, логин, url, заметки, название) из базы данных.
# uid = уникальный идентификатор (ID) - идентификатор, по которому осуществляется
# оперирование (поиск, редактирование и т. д.) с данными таблиц.

def excepthook(exc_type, exc_value, exc_tb):
    # Функция, которая печатает ошибку в работе приложения в консоль.
    tb = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    print("error catched!:")
    print("error message:\n", tb)


class Login(QMainWindow, Ui_LogWindow):
    # Переменная, отвечающая за смену окна.
    switch_window = QtCore.pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.setWindowTitle('P1QtPass')
        self.unlockBtn.clicked.connect(self.login)
        self.hideBtn.clicked.connect(self.hide_show)
        self.closeBtn.clicked.connect(self.close)
        self.masterKey.setEchoMode(QtWidgets.QLineEdit.Password)
        self.masterKey.textChanged.connect(self.clear_err)
        self.importBtn.triggered.connect(self.load_file)
        self.exportBtn.triggered.connect(self.save_file)

    def load_file(self):
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File', os.getenv('HOME'))
        with open(filename, 'r') as f:
            file_text = f.read()
            print(filename)

    def save_file(self):
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(self, 'Save File')
        with open(filename, 'w') as f:
            f.write("test")

    def clear_err(self):
        # Функция, очищающая строку вывода ошибок.
        if self.errLine.text():
            self.errLine.setText('')

    def close_button(self):
        # Функция, закрывающая приложение по нажатию кнопки.
        sys.exit()

    def hide_show(self):
        # Функция, показывающая/скрывающая поле ввода пароля, а также меняющая надпись на соответсвующей кнопке.
        if self.hideBtn.text() == 'Спрятать':
            self.masterKey.setEchoMode(QLineEdit.EchoMode.Password)
            self.hideBtn.setText('Показать')
        else:
            self.masterKey.setEchoMode(QLineEdit.EchoMode.Normal)
            self.hideBtn.setText('Спрятать')

    def login(self):
        # Функция, которая запускает начальные алгоритмы программы (подробнее в файле p1qtpass_main.py).
        if self.masterKey.text():
            master_key = self.masterKey.text()
            res = launch_p1qtpass(master_key)
            if res:
                self.check_pass(master_key)
            else:
                sys.exit()
        else:
            self.errLine.setText('Поле ввода не может быть пустым.')

    def keyPressEvent(self, e):
        # Функция, которая отслеживает нажатие клавиши Enter, после чего
        # работает также, как и кнопка открытия хранилища.
        if e.key() == QtCore.Qt.Key_Return:
            self.login()
        else:
            super().keyPressEvent(e)

    def check_pass(self, master):
        # Функция, которая проверяет мастер-ключ и после успешного ввода открывает хранилище.
        is_valid_master = check_valid_master_key(master)
        if not is_valid_master:
            self.errLine.setText('Неправильный мастер ключ.')
        else:
            self.switch_window.emit()


class MainWindow(QMainWindow, Ui_MainWindow):
    # Переменные, отвечающие за смену окон.
    switch_window_add = QtCore.pyqtSignal()
    switch_window_change = QtCore.pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.setWindowTitle('P1QtPass')
        self.searchName.textChanged.connect(self.filter_search)
        self.update_all()
        self.tableWidget.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tableWidget.customContextMenuRequested.connect(self.generate_menu_table)
        self.tableWidget.viewport().installEventFilter(self)
        self.databaseInfo.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.databaseInfo.customContextMenuRequested.connect(self.generate_menu_info)
        self.databaseInfo.viewport().installEventFilter(self)
        self.addBtn.clicked.connect(self.add_pass)
        self.changeMaster.clicked.connect(self.change_pass)
        self.to_edit = None
        self.selected_uid = None

    def change_pass(self):
        # Открытие окна смены пароля.
        self.switch_window_change.emit()

    def add_pass(self):
        # Открытие окна добавления пароля.
        self.switch_window_add.emit()

    def generate_menu_table(self, pos):
        # Функция, генерирующая таблицу с содержимым хранилища на виджете главного экрана.
        self.menu.exec_(self.tableWidget.mapToGlobal(pos))

    def generate_menu_info(self, pos):
        # Функция, генерирующая QTextBrowser с содержимым выделенной ячейки таблицы.
        self.menu.exec_(self.databaseInfo.mapToGlobal(pos))

    def eventFilter(self, source, event):
        # Функция, открывающая выкидывающееся меню с кнопками "Копировать",
        # "Редактировать", "Удалить" на виджете таблицы,
        # а также обрабатывает клики по databaseInfo и ячейкам таблицы.
        if (event.type() == QtCore.QEvent.MouseButtonPress and event.buttons() == QtCore.Qt.RightButton and
                source is self.tableWidget.viewport()):
            item = self.tableWidget.itemAt(event.pos())
            if item is not None:
                self.menu = QMenu(self)
                copy = self.menu.addAction('Копировать пароль')
                edit = self.menu.addAction('Редактировать')
                delete = self.menu.addAction('Удалить')
                copy.triggered.connect(lambda chk, item=item: self.copy_secret(item))
                edit.triggered.connect(lambda chk, item=item: self.edit_secret(item))
                delete.triggered.connect(lambda chk, item=item: self.delete_secret(item))
        elif (event.type() == QtCore.QEvent.MouseButtonPress and event.buttons() == QtCore.Qt.LeftButton and
              source is self.tableWidget.viewport()):
            item = self.tableWidget.itemAt(event.pos())
            if item is not None:
                self.show_info(item)
        elif (event.type() == QtCore.QEvent.MouseButtonPress and event.buttons() == QtCore.Qt.RightButton and
              source is self.databaseInfo.viewport()):
            self.menu = QMenu(self)
            copy = self.menu.addAction('Копировать пароль')
            copy.triggered.connect(lambda chk, uid=self.selected_uid: self.copy_secret(None, uid))
        return super(MainWindow, self).eventFilter(source, event)

    def get_row_by_uid(self, uid):
        # Функция, получающая секреты (без пароля) из базы данных по уникальному ID.
        con = sqlite3.connect("passwords.db")
        cur = con.cursor()
        res = cur.execute("""SELECT name, url, login, notes, uid
                             FROM passwords WHERE uid = ?""", (uid,)).fetchone()
        con.close()
        return res

    def get_secret_by_uid(self, uid):
        # Функция, получающая пароль из базы данных по уникальному ID.
        con = sqlite3.connect("passwords.db")
        cur = con.cursor()
        res = cur.execute("""SELECT password
                             FROM passwords WHERE uid = ?""", (uid,)).fetchone()[0].decode('utf-8')
        con.close()
        return res

    def copy_secret(self, item, uid=None):
        # Функция копирования пароля из соответствующей ячейки таблицы виджета.
        if uid is None:
            row = item.row()
            uid = self.tableWidget.item(row, 4).text()
        copy(runtime_ctx['encryptor'].decrypt(self.get_secret_by_uid(uid)).decode('utf-8'))

    def edit_secret(self, item):
        # Функция редактирования секретов из соответствующей ячейки таблицы виджета.
        row = item.row()
        uid = self.tableWidget.item(row, 4).text()
        self.to_edit = list(self.get_row_by_uid(uid)) + [runtime_ctx['encryptor'].decrypt
                                                         (self.get_secret_by_uid(uid)).decode('utf-8')]
        self.switch_window_add.emit()

    def update_all(self):
        # Функция, обновляющая виджет таблицы на главном экране.
        passwords_table = self.get_all_passwords()
        self.update_table(passwords_table)

    def delete_secret(self, item):
        # Функция удаления секретов из соответствующей ячейки таблицы виджета.
        row = item.row()
        uid = self.tableWidget.item(row, 4).text()
        con = sqlite3.connect("passwords.db")
        cur = con.cursor()
        cur.execute("""DELETE FROM passwords
                    WHERE uid = ?""", (uid,))
        con.commit()
        self.update_all()

    def show_info(self, item):
        # Функция, отображающая данные выбранной ячейки таблицы.
        row = item.row()
        uid = self.tableWidget.item(row, 4).text()
        self.selected_uid = uid
        information = self.get_row_by_uid(uid)
        self.databaseInfo.setText(f'Название: {information[0]}\nURL: {information[1]}\nЛогин: '
                                  f'{information[2]}\nЗаметки: {information[3]}\n'
                                  f'Пароль: ********')

    def filter_search(self):
        # Функция поиска паролей по базе данных через поле ввода.
        data = self.get_all_passwords()
        text = self.searchName.text()
        self.update_table(
            data if not text else list(filter(lambda x: text in x[0] or text in x[1] or text in x[2], data)))

    def get_all_passwords(self):
        # Функция получения всех данных базы данных для вывода их на виджет.
        con = sqlite3.connect("passwords.db")
        cur = con.cursor()
        secrets = cur.execute("""SELECT name, login, url, notes, uid FROM passwords
                              """).fetchall()
        con.close()
        return secrets

    def update_table(self, lst):
        # Функция обновления отоброжаемых данных на виджете.
        self.tableWidget.setRowCount(0)
        for n, row in enumerate(lst):
            row_position = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row_position)
            for m, item in enumerate(row):
                newitem = QTableWidgetItem(item)
                self.tableWidget.setItem(n, m, newitem)


class AddWindow(QMainWindow, Ui_addPassDialog):
    # Переменная, отвечающая за смену окна.
    switch_window = QtCore.pyqtSignal()

    def __init__(self, to_edit):
        super().__init__()
        self.setupUi(self)
        self.setWindowTitle('Добавление пароля')
        self.cancelButton.clicked.connect(self.close_wind)
        self.applyButton.clicked.connect(self.add_pass)
        self.generateButton.clicked.connect(self.generate_password)
        self.passwordEdit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pushButton.clicked.connect(self.hide_show)
        self.edit = False
        self.to_edit = to_edit
        if to_edit is not None:
            # Условие, определяющее, редактируется или добавляется пароль.
            self.fill_fields(to_edit)
            self.edit = True

    def closeEvent(self, e):
        # Функция, вызывающая закрытие текущего окна.
        self.close_wind()

    def fill_fields(self, to_edit):
        # Функция, отображающая данные редактироемого секрета в соответствующих полях при редактировании пароля.
        self.nameEdit.setText(to_edit[0])
        self.loginEdit.setText(to_edit[2])
        self.urlEdit.setText(to_edit[1])
        self.passwordEdit.setText(to_edit[-1])
        self.notesEdit.setPlainText(to_edit[3])

    def hide_show(self):
        # Функция, показывающая/скрывающая поле ввода пароля, а также меняющая надпись на соответсвующей кнопке.
        if self.pushButton.text() == 'Спрятать':
            self.passwordEdit.setEchoMode(QLineEdit.EchoMode.Password)
            self.pushButton.setText('Показать')
        else:
            self.passwordEdit.setEchoMode(QLineEdit.EchoMode.Normal)
            self.pushButton.setText('Спрятать')

    def generate_password(self):
        # Функция, генерирующая наджный пароль при нажатии кнопки.
        password = get_random_salt()
        self.passwordEdit.setText(password)

    def close_wind(self):
        # Функция, закрывающая окно.
        self.switch_window.emit()

    def add_pass(self):
        # Функция, которая вызывает изменение базы данных при редактировании/добавления пароля.
        name = self.nameEdit.text()
        login = self.loginEdit.text()
        url = self.urlEdit.text()
        password = self.passwordEdit.text()
        notes = self.notesEdit.toPlainText()
        if not self.edit:
            add_password(name, url, login, password, notes)
        else:
            uid = self.to_edit[-2]
            edit_password(name, url, login, password, notes, uid)
        self.switch_window.emit()


class ChangeWindow(QMainWindow, Ui_MasterChange):
    # Переменная, отвечающая за смену окна.
    switch_window = QtCore.pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.setWindowTitle('Изменение пароля')
        self.changeButton.clicked.connect(self.change_pass)
        self.keyOld.textChanged.connect(self.clear_err)
        self.keyNew1.textChanged.connect(self.clear_err)
        self.keyNew2.textChanged.connect(self.clear_err)
        self.keyOld.setEchoMode(QtWidgets.QLineEdit.Password)
        self.keyNew1.setEchoMode(QtWidgets.QLineEdit.Password)
        self.keyNew2.setEchoMode(QtWidgets.QLineEdit.Password)
        self.hideBtn.clicked.connect(self.hide_show)

    def hide_show(self):
        # Функция, показывающая/скрывающая поле ввода пароля, а также меняющая надпись на соответсвующей кнопке.
        if self.hideBtn.text() == 'Спрятать':
            self.keyOld.setEchoMode(QLineEdit.EchoMode.Password)
            self.keyNew1.setEchoMode(QLineEdit.EchoMode.Password)
            self.keyNew2.setEchoMode(QLineEdit.EchoMode.Password)
            self.hideBtn.setText('Показать')
        else:
            self.keyOld.setEchoMode(QLineEdit.EchoMode.Normal)
            self.keyNew1.setEchoMode(QLineEdit.EchoMode.Normal)
            self.keyNew2.setEchoMode(QLineEdit.EchoMode.Normal)
            self.hideBtn.setText('Спрятать')

    def clear_err(self):
        # Функция, очищающая строку вывода ошибок
        if self.errLabel.text():
            self.errLabel.setText('')

    def change_pass(self):
        # Функция, изменяющая мастер-ключ.
        new_pass = self.keyNew1.text()
        if self.keyNew1.text() == self.keyNew2.text():
            if check_valid_master_key(self.keyOld.text()):
                decrypted_passwords = get_all_passwords()
                runtime_ctx['encryptor'] = Encryptor(new_pass.encode())
                refresh_all_passwords(decrypted_passwords)
                runtime_ctx['config'] = Config()
                create_config()
                create_validation_key()
                self.switch_window.emit()
            else:
                self.errLabel.setText('Неправильный старый мастер ключ')
        else:
            self.errLabel.setText('Новые мастер ключи не совпадают')


class Controller:
    # Класс, отвечающий за переключение окон программы.
    def __init__(self):
        pass

    def show_login(self):
        self.login = Login()
        self.login.switch_window.connect(self.show_main)
        self.login.show()

    def show_main(self):
        self.main = MainWindow()
        self.main.switch_window_add.connect(lambda: self.show_add_dialog(self.main.to_edit))
        self.main.switch_window_change.connect(self.show_change_dialog)
        self.main.show()
        self.login.close()

    def show_add_dialog(self, to_edit):
        self.dial = AddWindow(to_edit)
        self.dial.switch_window.connect(self.close_dialog)
        self.dial.show()

    def show_change_dialog(self):
        self.dial = ChangeWindow()
        self.dial.switch_window.connect(self.close_dialog)
        self.dial.show()

    def close_dialog(self):
        self.dial.close()
        self.main.to_edit = None
        self.main.update_all()


def main():
    sys.excepthook = excepthook
    app = QtWidgets.QApplication(sys.argv)
    controller = Controller()
    controller.show_login()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
