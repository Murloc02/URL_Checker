import telebot
from main import predict

TOKEN = '6100411855:AAGRq3PAPIkUgMlxmpfWudXDfU8n3uTqmj8'
bot = telebot.TeleBot(TOKEN)


@bot.message_handler(content_types=['text'])
def get_text_messages(message):
    print_user(message)
    ans = predict(message.text)
    bot.send_message(message.from_user.id, ans)


def print_user(message):
    print(message.from_user.full_name, message.text, message.from_user.username)


if __name__ == '__main__':
    bot.polling(none_stop=True, interval=0)
