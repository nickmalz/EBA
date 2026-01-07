import psutil
import time
import logging
from datetime import datetime
# ================= НАСТРОЙКИ =================
LOG_FILE = 'behavior_monitor.log'
CPU_THRESHOLD = 80.0  # % загрузки ЦП, выше которого считаем аномалией
CPU_SUSPICION_LIMIT = 5  # Сколько раз подряд должна быть высокая нагрузка
DISK_WRITE_THRESHOLD = 5 * 1024 * 1024  # 5 МБ/сек скорость записи
CHECK_INTERVAL = 2  # Интервал проверки (сек)

# Белый список (процессы, которые мы игнорируем)
WHITELIST = ""


class ProcessMonitor:
    def __init__(self):
        self.history = {}  # История процессов: PID -> {data}
        self.is_running = True

    def check_miner(self, info):
        """Эвристика для обнаружения майнера"""
        pid = info['pid']
        cpu_percent = info['cpu_percent']

        # Если процесс новый, инициализируем счетчик
        if pid not in self.history:
            self.history[pid] = {'high_cpu_ticks': 0, 'last_write': 0}

        # Логика счетчика
        if cpu_percent > CPU_THRESHOLD:
            self.history[pid]['high_cpu_ticks'] += 1
        else:
            # Если нагрузка упала, уменьшаем счетчик (или сбрасываем)
            if self.history[pid]['high_cpu_ticks'] > 0:
                self.history[pid]['high_cpu_ticks'] -= 1

        # Проверка порога срабатывания
        if self.history[pid]['high_cpu_ticks'] >= CPU_SUSPICION_LIMIT:
            self.alert(
                f"Подозрение на МАЙНЕР: {info['name']} (PID: {pid}) грузит ЦП на {cpu_percent}% уже долгое время!")

    def check_ransomware(self, proc, info, interval):
        """Эвристика для обнаружения шифровальщика"""
        pid = info['pid']
        try:
            io = proc.io_counters()  # Получаем текущие счетчики
            current_write = io.write_bytes

            if pid in self.history:
                prev_write = self.history[pid].get('last_write', 0)
                # Если это не первый замер
                if prev_write > 0:
                    delta = current_write - prev_write
                    speed = delta / interval  # Байт в секунду

                    if speed > DISK_WRITE_THRESHOLD:
                        self.alert(
                            f"Подозрение на RANSOMWARE: {info['name']} (PID: {pid}) пишет на диск со скоростью {speed / 1024 / 1024:.2f} МБ/с")

            # Обновляем историю
            self.history[pid]['last_write'] = current_write

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass  # Процесс мог завершиться или быть системным
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def analyze_cpu(self, proc, pid, name):
    """Проверка на майнер"""
    try:
        # Получаем % загрузки. В psutil это значение с момента последнего вызова.
        cpu_usage = proc.cpu_percent()

        if cpu_usage > CPU_THRESHOLD:
            self.processes[pid]['cpu_ticks'] += 1
        else:
            # Если нагрузка упала, плавно уменьшаем подозрение
            if self.processes[pid]['cpu_ticks'] > 0:
                self.processes[pid]['cpu_ticks'] -= 1

        # Если счетчик превысил порог
        if self.processes[pid]['cpu_ticks'] >= CPU_SUSPICION_LIMIT:
            log_alert(f"MAJNER DETECTED: Процесс '{name}' (PID: {pid}) грузит ЦП на {cpu_usage}% в течение {CPU_SUSPICION_LIMIT * CHECK_INTERVAL} сек!")
            # Сброс, чтобы не спамить алертами каждую секунду (или можно реализовать кулдаун)
            self.processes[pid]['cpu_ticks'] = CPU_SUSPICION_LIMIT - 2

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass


def analyze_disk(self, proc, pid, name):
    """Проверка на шифровальщик"""
    try:
        io = proc.io_counters()
        if not io: return

        curr_write = io.write_bytes
        prev_write = self.processes[pid]['last_write_bytes']
        curr_time = time.time()
        prev_time = self.processes[pid]['last_check_time']

        # Вычисление скорости
        time_delta = curr_time - prev_time
        if time_delta > 0:
            bytes_delta = curr_write - prev_write
            write_speed = bytes_delta / time_delta  # Байт в секунду

            if write_speed > DISK_WRITE_THRESHOLD:
                log_alert(
                    f"RANSOMWARE DETECTED: Процесс '{name}' (PID: {pid}) аномальная запись: {write_speed / 1024 / 1024:.2f} MB/s")

        # Обновляем сохраненное состояние
        self.processes[pid]['last_write_bytes'] = curr_write
        self.processes[pid]['last_check_time'] = curr_time

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

def cleanup(self, current_pids):
    """Удаление данных о завершенных процессах"""
    known_pids = list(self.processes.keys())
    for pid in known_pids:
        if pid not in current_pids:
            del self.processes[pid]


def main():
    print(f"Запуск монитора... (Интервал: {CHECK_INTERVAL}с)")
    tracker = ProcessMonitor()

    try:
        while True:
            tracker.check_miner([1])
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        print("\nМониторинг остановлен.")


if __name__ == "__main__":
    main()