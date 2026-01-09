import time
import os
import random
import string
import sys

def generate_random_data(size_mb):
    """Генерирует рандомные данные"""
    size_bytes = size_mb * 1024 * 1024
    data = ''.join(random.choices(string.ascii_letters + string.digits, k=size_bytes))
    return data.encode('utf-8')

def disk_intensive_task():
    """Симулирует работу шифровальщика с интенсивной записью на диск"""
    print(f"Запуск процесса с интенсивной записью на диск (PID: {os.getpid()})")

    counter = 0
    while True:
        # Генерируем большой объем случайных данных
        data = generate_random_data(10)  # 10 МБ данных

        # Записываем во временный файл
        filename = f"temp_file_{counter}.tmp"
        try:
            with open(filename, 'wb') as f:
                f.write(data)

            # Читаем файл обратно
            with open(filename, 'rb') as f:
                read_data = f.read()

            # Удаляем файл
            os.remove(filename)

            counter += 1

            # Выводим прогресс каждые 5 итераций
            if counter % 5 == 0:
                print(f"Выполнено {counter} итераций работы с диском")

        except Exception as e:
            print(f"Ошибка при работе с диском: {e}")

        # Небольшая задержка, чтобы не заблокировать систему полностью
        time.sleep(0.05)

if __name__ == "__main__":
    try:
        # Меняем имя процесса, чтобы выглядеть более подозрительно
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleTitleW("CryptoLocker")
        except:
            pass
        disk_intensive_task()
    except KeyboardInterrupt:
        print("\nПроцесс с интенсивной записью на диск остановлен.")
        sys.exit(0)