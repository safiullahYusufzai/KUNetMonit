import tkinter as tk
from PIL import Image, ImageTk
import time

class SplashScreen(tk.Toplevel):
    def __init__(self, parent, image_path, duration=5000):
        super().__init__(parent)
        self.duration = duration
        self.start_time = 0

        self.overrideredirect(True)

        # Load and resize image
        try:
            image = Image.open(image_path).resize((1024, 768))
            self.splash_img = ImageTk.PhotoImage(image)
        except Exception as e:
            print(f"Error loading image: {e}")
            self.destroy()
            return

        # Center the window
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - 1024) // 2
        y = (sh - 768) // 2
        self.geometry(f"1024x768+{x}+{y}")

        # === Draw everything on Canvas ===
        self.canvas = tk.Canvas(self, width=1024, height=768, highlightthickness=0)
        self.canvas.pack()

        self.canvas.create_image(0, 0, anchor="nw", image=self.splash_img)

        # Create loading bar outline
        self.canvas.create_rectangle(100, 720, 924, 740, outline="aqua", width=1)
        self.bar_fill = self.canvas.create_rectangle(100, 720, 100, 740, fill="aqua", width=0)

        self.after_idle(self.start_loading_bar)

    def start_loading_bar(self):
        self.start_time = time.perf_counter()
        self.update_progress()

    def update_progress(self):
        elapsed = (time.perf_counter() - self.start_time) * 1000  # in ms
        progress = min(1.0, elapsed / self.duration)
        fill_width = int(824 * progress)
        self.canvas.coords(self.bar_fill, 100, 720, 100 + fill_width, 740)

        if progress >= 1.0:
            self.destroy()
        else:
            self.after(30, self.update_progress)