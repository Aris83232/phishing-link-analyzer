#just the entry point, all will start here

import tkinter as tk
from gui import PhishingLinkAnalyzer

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingLinkAnalyzer(root)
    root.mainloop()