import tkinter as tk
from tkinter import ttk, messagebox
import concurrent.futures
import threading
from scapy.all import ARP, Ether, srp
import queue

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")

        self.label = tk.Label(root, text="Enter IP Range:")
        self.label.pack(pady=10)

        self.entry = tk.Entry(root, width=30)
        self.entry.insert(0, "192.168.1.1-255")
        self.entry.pack(pady=10)

        self.timeout_label = tk.Label(root, text="Enter Timeout (seconds):")
        self.timeout_label.pack(pady=5)
        self.timeout_entry = tk.Entry(root, width=10)
        self.timeout_entry.insert(0, "3")  # Значение по умолчанию
        self.timeout_entry.pack(pady=10)

        self.scan_button = tk.Button(root, text="Scan", command=self.start_scan_thread)
        self.scan_button.pack(pady=10)

        self.result_tree = ttk.Treeview(root)
        self.result_tree["columns"] = ("IP", "MAC")
        self.result_tree.column("#0", width=0, stretch=tk.NO)
        self.result_tree.column("IP", anchor=tk.W, width=150)
        self.result_tree.column("MAC", anchor=tk.W, width=150)

        self.result_tree.heading("#0", text="", anchor=tk.W)
        self.result_tree.heading("IP", text="IP", anchor=tk.W)
        self.result_tree.heading("MAC", text="MAC", anchor=tk.W)

        self.result_tree.pack(pady=10)

        self.thread_label = tk.Label(root, text="Select number of threads:")
        self.thread_label.pack(pady=5)
        self.thread_combo = ttk.Combobox(root, values=["50", "100"])
        self.thread_combo.set("50")
        self.thread_combo.pack(pady=10)

        self.result_queue = queue.Queue()

        # Словарь для хранения результатов в виде массивов, где ключ - ip_range
        self.results_dict = {}

        # Список для хранения уникальных результатов в виде кортежей (ip, mac)
        self.unique_results = []

        # Индикатор для отображения всего словаря или только результатов текущего ip_range
        self.show_all_results = True
        self.show_all_button = tk.Button(root, text="Show All Results", command=self.toggle_show_all, relief=tk.FLAT)
        self.show_all_button.pack(pady=5)

    def start_scan_thread(self):
        ip_range = self.entry.get()
        if not ip_range:
            messagebox.showwarning("Warning", "Please enter an IP range.")
            return

        # Обнуляем результаты для текущего ip_range
        self.results_dict[ip_range] = []
        self.unique_results = []

        self.result_tree.delete(*self.result_tree.get_children())

        num_threads = int(self.thread_combo.get())
        timeout = float(self.timeout_entry.get())  # Преобразуем значение timeout в число
        self.scan_thread = threading.Thread(target=self.scan_ip_range, args=(ip_range, num_threads, timeout))
        self.scan_thread.start()

        self.root.after(100, self.check_result_queue)

    def scan_ip_range(self, ip_range, num_threads, timeout):
        ip_list = ip_range.split('-')
        ip_template = ip_list[0].rsplit('.', 1)[0]

        start_ip, end_ip = ip_list[0][-1], ip_list[-1]
        devices = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(self.scan, f"{ip_template}.{i}", timeout) for i in range(int(start_ip), int(end_ip) + 1)]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    # Помещаем результат в очередь
                    self.result_queue.put((ip_range, result))

        # Помещаем специальный элемент для определения завершения сканирования
        self.result_queue.put((ip_range, None))

    def check_result_queue(self):
        try:
            while True:
                ip_range, result = self.result_queue.get_nowait()
                if result is None:
                    # Сканирование для текущего ip_range завершено
                    self.result_tree.insert("", "end", values=("", ""))  # Empty line for result separation
                    self.result_tree.insert("", "end", values=(f"Scan completed for {ip_range}.", ""))
                    messagebox.showinfo("Scan Completed", f"Scan completed for {ip_range}.")
                    break
                else:
                    # Обновляем результаты в соответствии с текущим состоянием
                    if self.show_all_results or ip_range == self.entry.get():
                        if result not in self.unique_results:
                            self.unique_results.append(result)
                            self.results_dict[ip_range].append(result)
                            self.result_tree.insert("", "end", values=(result['ip'], result['mac']))
                            # Обновляем GUI
                            self.root.update_idletasks()
        except queue.Empty:
            self.root.after(100, self.check_result_queue)

    def scan(self, ip, timeout):
        try:
            result = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=timeout, verbose=0)[0]

            if result:
                return {'ip': result[0][1].psrc, 'mac': result[0][1].hwsrc}
        except Exception as e:
            print(f"An error occurred: {e}")
        return None

    def toggle_show_all(self):
        # Переключаем состояние между отображением всех результатов и результатов только для текущего ip_range
        self.show_all_results = not self.show_all_results
        self.update_display()

    def update_display(self):
        # Очищаем Treeview и отображаем результаты в соответствии с текущим состоянием
        self.result_tree.delete(*self.result_tree.get_children())
        for ip_range, results in self.results_dict.items():
            if self.show_all_results or ip_range == self.entry.get():
                for result in results:
                    self.result_tree.insert("", "end", values=(result['ip'], result['mac']))

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()