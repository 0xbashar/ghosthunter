import logging, sys
from colorama import Fore, Style, init
init()

class ColorFormatter(logging.Formatter):
    def format(self, r):
        c = {"INFO": Fore.CYAN, "WARN": Fore.YELLOW, "ERR": Fore.RED,
             "DEBUG": Fore.MAGENTA, "SUCCESS": Fore.GREEN}.get(r.levelname, "")
        return f"{c}[{r.levelname}]{Style.RESET_ALL} {r.getMessage()}"

class Logger:
    @staticmethod
    def get_logger(name="ghosthunter"):
        l = logging.getLogger(name)
        if l.handlers: return l
        l.setLevel("DEBUG")
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(ColorFormatter())
        l.addHandler(h)
        l.success = lambda m, l=l: l.info(m) if False else l.log(25, m)
        logging.addLevelName(25, "SUCCESS")
        return l

    @staticmethod
    def _emit(lvl, msg, ctx="ghosthunter"):
        getattr(Logger.get_logger(ctx), lvl)(msg)

    @staticmethod
    def info(m):    Logger._emit("info", m)
    @staticmethod
    def warn(m):    Logger._emit("warning", m)
    @staticmethod
    def err(m):     Logger._emit("error", m)
    @staticmethod
    def success(m): Logger._emit("success", m)
    @staticmethod
    def debug(m):   Logger._emit("debug", m)
    @staticmethod
    def phase(m):   print(f"\n{Fore.BLUE}━━━ {m} ━━━{Style.RESET_ALL}")
    @staticmethod
    def header(m):  print(f"\n{Fore.MAGENTA}╔{'═'*(len(m)+2)}╗\n║ {m} ║\n╚{'═'*(len(m)+2)}╝{Style.RESET_ALL}")
