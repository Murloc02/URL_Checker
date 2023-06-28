from tensorflow import keras
from tensorflow.keras.layers import Dense, Flatten
import pandas as pd
import numpy as np


from NewConvert import convert_url


def input_file(path):
    file = pd.read_csv(path)
    x = file.drop(['url', 'type', 'category'], axis=1)
    y = file['category']
    return x, y


def train():
    x, y = input_file('updated.csv')
    y = keras.utils.to_categorical(y, 4)

    model = keras.Sequential([
        Flatten(input_shape=(20, 1)),
        Dense(11, activation='relu'),
        Dense(4, activation='softmax')
    ])

    # print(model.summary())  # вывод структуры НС в консоль

    model.compile(optimizer='adam',
                  loss='binary_crossentropy',
                  metrics=['binary_accuracy'])

    model.fit(x, y, batch_size=200, epochs=5, validation_split=0.1)
    model.save('model')


# функция для предсказания по обученной модели
def predict(url: str):

    model = keras.models.load_model('model')

    url = np.reshape(convert_url(url), (1, 20))

    res = model.predict(url)[0]
    arg = np.argmax(res)

    url_types = {0: 'Безопасный', 1: 'Испорченный', 2: 'Фишинговый', 3: 'Вредоносный'}

    ans = url_types[arg] + ' с вероятностью ' + str(int(res[arg] * 100)) + ' %'

    return ans


if __name__ == "__main__":
    train()

