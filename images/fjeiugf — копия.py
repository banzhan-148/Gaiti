import telebot
from telebot import types
import logging

BOT_API = '8113514230:AAEAJGw4wj39nhKEEgkHVOpBF3sZg39IfB4'

bot = telebot.TeleBot(BOT_API)
telebot.logger.setLevel(logging.INFO)

storage = dict()





@bot.message_handler(commands=['start'])
def start(message):
    markup = types.InlineKeyboardMarkup()
    btn1 = types.InlineKeyboardButton('Винилы для машин', callback_data='vinils')
    btn2 = types.InlineKeyboardButton('Настройки для машин', callback_data='nastroyki')
    btn20 = types.InlineKeyboardButton('IP серверов', callback_data='ip')
    btn22 = types.InlineKeyboardButton('Скачка шаблонов',  url="https://web.telegram.org/a/#-1002623587093")
    markup.add(btn1, btn2, btn20, btn22)
    bot.send_message(message.chat.id, 'Привет! Это бот для подбора тюнинга ваших машин на сервере Mta/Drift Paradise.', reply_markup=markup)

@bot.callback_query_handler(func=lambda call: True)
def callback_inline(call):
    if call.data == 'vinils':
        markup1 = types.InlineKeyboardMarkup()
        btn3 = types.InlineKeyboardButton('Toyota Altezza', callback_data='Altezza')
        btn4 = types.InlineKeyboardButton('Toyota MarK II', callback_data='Mark_II')
        btn5 = types.InlineKeyboardButton('BMW E36', callback_data='BMW_E36')
        btn6 = types.InlineKeyboardButton('Silvia 15', callback_data='S15')
        btn7 = types.InlineKeyboardButton('GT-R R34', callback_data='GTR')
        btn8 = types.InlineKeyboardButton('Назад', callback_data='back')
        markup1.add(btn3, btn4, btn5, btn6, btn7, btn8)
        bot.send_message(call.message.chat.id, 'Выберите машину:', reply_markup=markup1)

    elif call.data == 'back':
        markup = types.InlineKeyboardMarkup()
        btn1 = types.InlineKeyboardButton('Винилы для машин', callback_data='vinils')
        btn2 = types.InlineKeyboardButton('Настройки для машин', callback_data='nastroyki')
        btn20 = types.InlineKeyboardButton('IP серверов', callback_data='ip')
        btn22 = types.InlineKeyboardButton('Скачка шаблонов',  url="https://web.telegram.org/a/#-1002623587093")
        markup.add(btn1, btn2, btn20, btn22)
        bot.send_message(call.message.chat.id, 'Привет! Это бот для подбора тюнинга ваших машин на сервере Mta/Drift Paradise.', reply_markup=markup)


    elif call.data == 'back_car':
        markup1 = types.InlineKeyboardMarkup()
        btn4 = types.InlineKeyboardButton('Toyota Altezza', callback_data='Altezza')
        btn5 = types.InlineKeyboardButton('Toyota MarK II', callback_data='Mark_II')
        btn6 = types.InlineKeyboardButton('BMW E36', callback_data='BMW_E36')
        btn7 = types.InlineKeyboardButton('Silvia 15', callback_data='S15')
        btn8 = types.InlineKeyboardButton('GT-R R34', callback_data='GTR')
        btn9 = types.InlineKeyboardButton('Назад', callback_data='back')
        markup1.add(btn4, btn5, btn6, btn7, btn8, btn9)
        bot.send_message(call.message.chat.id, 'Выберите машину:', reply_markup=markup1)

    elif call.data == 'nakl':
        markup12 = types.InlineKeyboardMarkup()
        btn21 = types.InlineKeyboardButton('Назад', callback_data='back')
        markup12.add(btn21)
        bot.send_message(call.message.chat.id, 'Шаблоны наклеек', reply_markup=markup12)

    elif call.data == 'Altezza':
        markup2 = types.InlineKeyboardMarkup()
        btn7 = types.InlineKeyboardButton('Назад', callback_data='back_car')
        media = [telebot.types.InputMediaPhoto(media=open('altezza1.jpg', 'rb')),
        telebot.types.InputMediaPhoto(media=open('altezza2.jpg', 'rb')),
        telebot.types.InputMediaPhoto(media=open('altezza3.jpg', 'rb'))]
        markup2.add(btn7)
        bot.send_media_group(call.message.chat.id, media)
        bot.send_message(call.message.chat.id, 'Винил для Toyota Altezza', reply_markup=markup2)

    elif call.data == 'Mark_II':
        markup3 = types.InlineKeyboardMarkup()
        btn8 = types.InlineKeyboardButton('Назад', callback_data='back_car')
        media = [telebot.types.InputMediaPhoto(media=open('markII1.jpg', 'rb')),
        telebot.types.InputMediaPhoto(media=open('markII2.jpg', 'rb')),
        telebot.types.InputMediaPhoto(media=open('markII3.jpg', 'rb'))]
        markup3.add(btn8)
        bot.send_media_group(call.message.chat.id, media)
        bot.send_message(call.message.chat.id, 'Винил для Toyota MarK II', reply_markup=markup3)

    elif call.data == 'BMW_E36':
        markup4 = types.InlineKeyboardMarkup()
        btn9 = types.InlineKeyboardButton('Назад', callback_data='back_car')
        media = [telebot.types.InputMediaPhoto(media=open('bmwE361.jpg', 'rb')),
        telebot.types.InputMediaPhoto(media=open('bmwE362.jpg', 'rb')),
        telebot.types.InputMediaPhoto(media=open('bmwE363.jpg', 'rb'))]
        markup4.add(btn9)
        bot.send_media_group(call.message.chat.id, media)
        bot.send_message(call.message.chat.id, 'Винил для BMW E36', reply_markup=markup4)

    elif call.data == 'S15':
        markup5 = types.InlineKeyboardMarkup()
        btn10 = types.InlineKeyboardButton('Назад', callback_data='back_car')
        media = [telebot.types.InputMediaPhoto(media=open('s151.jpg', 'rb')),
        telebot.types.InputMediaPhoto(media=open('s152.jpg', 'rb')),
        telebot.types.InputMediaPhoto(media=open('s153.jpg', 'rb'))]
        markup5.add(btn10)
        bot.send_media_group(call.message.chat.id, media)
        bot.send_message(call.message.chat.id, 'Винил для Silvia 15', reply_markup=markup5)

    elif call.data == 'GTR':
        markup6 = types.InlineKeyboardMarkup()
        btn11 = types.InlineKeyboardButton('Назад', callback_data='back_car')
        media = [telebot.types.InputMediaPhoto(media=open('gtr1.jpg', 'rb')),
        telebot.types.InputMediaPhoto(media=open('gtr2.jpg', 'rb')),
        telebot.types.InputMediaPhoto(media=open('gtr3.jpg', 'rb'))]
        markup6.add(btn11)
        bot.send_media_group(call.message.chat.id, media)
        bot.send_message(call.message.chat.id, 'Винил для GT-R R34', reply_markup=markup6)

    elif call.data == 'nastroyki':
        markup6 = types.InlineKeyboardMarkup()
        btn10 = types.InlineKeyboardButton('Toyota Altezza', callback_data='Altezza_nastroyki')
        btn11 = types.InlineKeyboardButton('Toyota MarK II', callback_data='Mark_II_nastroyki')
        btn12 = types.InlineKeyboardButton('BMW E36', callback_data='BMW_E36_nastroyki')
        btn13 = types.InlineKeyboardButton('Silvia 15', callback_data='S15_nastroyki')
        btn14 = types.InlineKeyboardButton('GT-R R34', callback_data='GTR_nastroyki')
        btn15 = types.InlineKeyboardButton('Назад', callback_data='back')
        markup6.add(btn10,btn11, btn12, btn13, btn14)
        bot.send_message(call.message.chat.id, 'Выберите машину для настроек:', reply_markup=markup6)

    elif call.data == 'Altezza_nastroyki':
        markup7 = types.InlineKeyboardMarkup()
        btn16 = types.InlineKeyboardButton('Назад', callback_data='back_nastroyki')
        markup7.add(btn16)
        bot.send_message(call.message.chat.id, '''
Тоуota Altezza~

Жесткость подвески: 0.95

Ходовая масса: 11910.1

Центр массы по оси Z: - 0.212

Ускорение двигателя: 28.905

Центр массы по оси Y: - 0.22

Масса: 10004.3

Смещение сцепления: 0.475

Пропорциональность подвески: 0.335

Высота подвески: - 0.06

Угол поворота колеса: 57.005

~Комментарий к настройке~

Стабильная настройка, алька тяжелая, перекладывается резко (но можно сделать
рещё), ускоряется хорошо, корректировок минимум, спокойно едет в тандеме с 15,
14 и 13 сильвиями. Можно доработать, в нелегалах тоже можно участвовать, но не
стоит ждать космических результатов, настройка тяжелая, но плавная и приятная.''', reply_markup=markup7)

    elif call.data == 'back_nastroyki':
        markup5 = types.InlineKeyboardMarkup()
        btn11 = types.InlineKeyboardButton('Toyota Altezza', callback_data='Altezza_nastroyki')
        btn12 = types.InlineKeyboardButton('Toyota MarK II', callback_data='Mark_II_nastroyki')
        btn13 = types.InlineKeyboardButton('BMW E36', callback_data='BMW_E36_nastroyki')
        btn14 = types.InlineKeyboardButton('Silvia 15', callback_data='S15_nastroyki')
        btn15 = types.InlineKeyboardButton('GT-R R34', callback_data='GTR')
        btn16 = types.InlineKeyboardButton('Назад', callback_data='back')
        markup5.add(btn11,btn12, btn13, btn14, btn15, btn16)
        bot.send_message(call.message.chat.id, 'Выберите машину для настроек:', reply_markup=markup5)
    
    elif call.data == 'Mark_II_nastroyki':
        markup8 = types.InlineKeyboardMarkup()
        btn17 = types.InlineKeyboardButton('Назад', callback_data='back_nastroyki')
        markup8.add(btn17)
        bot.send_message(call.message.chat.id, '''
Toyota Mark II jzx100~

Жесткость подвески: 1  
Ходовая масса: 14000  
Центр массы по оси Z: - 0.22  
Ускорение двигателя: 27  
Центр массы по оси Y: - 0.3  
Масса: 12000  
Смещение сцепления: 0.44  
Пропорциональность подвески: 0.4  
Высота подвески: - 0.08  
Угол поворота колеса: 60  

~Комментарий к настройке~

После редактирования настроек на Марк, получилось создать, что-то такое на чем можно и горы катнуть и парный заехать без сложностей, споты едет очень хорошо, быстро ускоряется и легко контролируется!''', reply_markup=markup8)
    
    elif call.data == 'BMW_E36_nastroyki':
        markup9 = types.InlineKeyboardMarkup()
        btn16 = types.InlineKeyboardButton('Назад', callback_data='back_nastroyki')
        markup9.add(btn16)
        bot.send_message(call.message.chat.id, '''
BMW E36~

Жесткость подвески: 0.95  
Ходовая масса: 11000  

Центр массы по оси Z:- 0.21  
Ускорение двигателя: 29  
Центр массы по оси Y:- 0.37  
Масса: 10000  
Смещение сцепления: 0.44  
Пропорциональность подвески: 0.418  
Высота подвески: - 0.12  
Угол поворота колеса: 60  

~Комментарий к настройке~

Отличная настройка, откатал несколько нелегов, и все удачно, топ 3 стабильно, едет бодро, ускоряется хорошо, углы держит, бекварды, все, что нужно.''', reply_markup=markup9)

    elif call.data == 'S15_nastroyki':
        markup10 = types.InlineKeyboardMarkup()
        btn17 = types.InlineKeyboardButton('Назад', callback_data='back_nastroyki')
        markup10.add(btn17)
        bot.send_message(call.message.chat.id, '''
Nissan Silvia S15~

Жесткость подвески: 1.04  
Ходовая масса: 13680.9  
Центр массы по оси Z: - 0.22  
Ускорение двигателя: 30  
Центр массы по оси Y: - 0.415  
Масса: 10000  

Смещение сцепления: 0.41  
Пропорциональность подвески: 0.499  
Высота подвески: - 0.175  
Угол поворота колеса: 55.535  

~Комментарий к настройке~

Да, получился трактор, для РДС, но, только в таком конфиге пропорции и высоты подвески 15 начали ехать в лоу угле, более ли менее. Я думаю эта настройка идеально подойдет для гор, споты ездить не советую, т.к. очень тяжелая в перекладках. Для Трансы, настройка будет бомбовая!''', reply_markup=markup10)

    elif call.data == 'GTR_nastroyki':
        markup11 = types.InlineKeyboardMarkup()
        btn18 = types.InlineKeyboardButton('Назад', callback_data='back_nastroyki')
        markup11.add(btn18)
        bot.send_message(call.message.chat.id, '''
Nissan GTR R34~
Жесткость подвески: 0.95
Ходовая масса: 11000
Центр массы по оси Z: - 0.22
Ускорение двигателя: 30
Центр массы по оси Y: - 0.299
Масса: 10805.9
Смещение сцепления: 0.436
Пропорциональность подвески: 0.387
Высота подвески: - 0.054
Угол поворота колеса: 60
~Комментарий к настройке~
Настройка для гор. Для спотов конечно, уже дело привычки, но для гор самое то. А споты довольно тяжко проходит.''', reply_markup=markup11)
        
    elif call.data == 'ip':
        markup12 = types.InlineKeyboardMarkup()
        btn_back = types.InlineKeyboardButton('Назад', callback_data='back')
        markup12.add(btn_back)
        bot.send_message(call.message.chat.id, '''
IP адреса серверов Drift Paradise:

Основной сервер: 51.254.25.23:22003
Тестовый сервер: 51.254.25.23:22004
Сервер с модами: 51.254.25.23:22005

Для подключения в MTA:
1. Нажмите "Бы  строе подключение"
2. Введите IP адрес
3. Нажмите "Подключиться"
''', reply_markup=markup12)
        

    



bot.polling()