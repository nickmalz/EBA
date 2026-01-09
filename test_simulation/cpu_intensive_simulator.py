import time
import math
import os
import sys

def cpu_intensive_task():
    """Симулирует майнинг с высокой загрузкой процессора"""
    print(f"Запуск процесса с высокой загрузкой ЦП (PID: {os.getpid()})")

    counter = 0
    while True:
        # Выполняем вычисления, нагружающие процессор
        result = 0
        for i in range(1000000):
            result += math.sqrt(i) * math.sin(i)

        counter += 1

        # Печатаем прогресс каждые 10 итераций
        if counter % 10 == 0:
            print(f"Выполнено {counter} итераций ресурсоемкой работы")

        # Небольшая задержка, чтобы не заблокировать систему полностью
        time.sleep(0.01)

if __name__ == "__main__":
    try:
        # Изменяем имя процесса, чтобы выглядеть более подозрительно
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleTitleW("SystemUpdater")
        except:
            pass
        cpu_intensive_task()
    except KeyboardInterrupt:
        print("\nПроцесс с высокой загрузкой ЦП остановлен.")
        sys.exit(0)