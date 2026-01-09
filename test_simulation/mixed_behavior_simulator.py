import time
import math
import os
import random
import string
import sys

def mixed_behavior_task():
    """Симулирует комбинированное вредоносное поведение - загрузка ЦП и диска"""
    print(f"Запуск процесса с комбинированным поведением (PID: {os.getpid()})")

    counter = 0
    while True:
        # Вычисления, нагружающие процессор
        result = 0
        for i in range(500000):
            result += math.sqrt(i) * math.sin(i)

        # Операция с интенсивной записью на диск
        data = ''.join(random.choices(string.ascii_letters + string.digits, k=5*1024*1024)).encode('utf-8')  # 5МБ

        filename = f"mixed_temp_{counter}.tmp"
        try:
            # Записываем данные в файл
            with open(filename, 'wb') as f:
                f.write(data)

            # Читаем обратно
            with open(filename, 'rb') as f:
                read_data = f.read()

            # Удаляем файл
            os.remove(filename)

        except Exception as e:
            print(f"Ошибка при комбинированной операции: {e}")

        counter += 1

        # Печатаем прогресс каждые 10 итераций
        if counter % 10 == 0:
            print(f"Выполнено {counter} итераций комбинированной работы")

        # Небольшая задержка
        time.sleep(0.02)

if __name__ == "__main__":
    try:
        # Изменяем имя процесса, чтобы выглядеть более подозрительно
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleTitleW("DataEncryptor")
        except:
            pass
        mixed_behavior_task()
    except KeyboardInterrupt:
        print("\nПроцесс с комбинированным поведением остановлен.")
        sys.exit(0)