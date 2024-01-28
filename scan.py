import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
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
        self.thread_combo = ttk.Combobox(root, values=["5", "10", "20", "50"])
        self.thread_combo.set("50")
        self.thread_combo.pack(pady=10)

        self.result_queue = queue.Queue()

        # Список для хранения уникальных результатов в виде кортежей (ip, mac)
        self.unique_results = []

    def start_scan_thread(self):
        ip_range = self.entry.get()
        if not ip_range:
            messagebox.showwarning("Warning", "Please enter an IP range.")
            return

        self.result_tree.delete(*self.result_tree.get_children())

        num_threads = int(self.thread_combo.get())
        self.unique_results = []
        self.scan_thread = threading.Thread(target=self.scan_ip_range, args=(ip_range, num_threads))
        self.scan_thread.start()

        self.root.after(100, self.check_result_queue)

    def scan_ip_range(self, ip_range, num_threads):
        ip_list = ip_range.split('-')
        ip_template = ip_list[0].rsplit('.', 1)[0]

        start_ip, end_ip = ip_list[0][-1], ip_list[-1]
        devices = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(self.scan, f"{ip_template}.{i}") for i in range(int(start_ip), int(end_ip) + 1)]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    # Помещаем результат в очередь
                    self.result_queue.put(result)

        # Помещаем специальный элемент для определения завершения сканирования
        self.result_queue.put(None)

    def check_result_queue(self):
        try:
            while True:
                result = self.result_queue.get_nowait()
                if result is None:
                    # Сканирование завершено
                    self.result_tree.insert("", "end", values=("", ""))  # Empty line for result separation
                    self.result_tree.insert("", "end", values=("Scan completed.", ""))
                    break
                else:
                    # Отображаем результат в Treeview
                    if (result['ip'], result['mac']) not in self.unique_results:
                        self.unique_results.append((result['ip'], result['mac']))
                        self.result_tree.insert("", "end", values=(result['ip'], result['mac']))
                        # Обновляем GUI
                        self.root.update_idletasks()
        except queue.Empty:
            self.root.after(100, self.check_result_queue)

    def scan(self, ip):
        try:
            result = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=3, verbose=0)[0]

            if result:
                return {'ip': result[0][1].psrc, 'mac': result[0][1].hwsrc}
        except Exception as e:
            print(f"An error occurred: {e}")
        return None

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()