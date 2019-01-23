import threading
import logging
log = logging.getLogger(__name__)

class HighLowSemaphore:
    lock = threading.Lock()
    shares_held = 0
    high_watermark = 15  # This is the max number of dumps we expect to find in memdump_tmp.  Should be at most 90% of the FS
    low_watermark = 5
    water_gate = False

    def __init__(self):
        pass

    def acquire(self):
        self.m_log("Attempting to acquire semaphore lock")
        with self.lock:
            if self.water_gate:  # it happened, okay?
                if self.shares_held < self.low_watermark:
                    self.m_log("Water gate is closed and semaphore below low watermark, opening gate")
                    self.water_gate = False
                    self.shares_held += 1
                    return True
            else:
                if self.shares_held < self.high_watermark:
                    self.m_log("Water gate is open and semaphore below high watermark")

                    self.shares_held += 1
                    if self.shares_held >= self.high_watermark:
                        self.m_log("Water gate is open and semaphore reached watermark. Closing gate")

                        self.water_gate = True
                    return True
            self.m_log("Couldn't acquire a share.")
            return False

    def m_log(self, message):
        log.debug(message + " Water Gate: {0}, Low Watermark: {1}, High Watermark: {2}, Current Shares Held: {3}, Object ID: {4}".format("Closed" if self.water_gate else "Open", self.low_watermark, self.high_watermark, self.shares_held, id(self)))

    def release(self):
        with self.lock:
            if self.shares_held <= 0:
                log.error("Shares held is 0 or less, wtf?")
            self.m_log("Releasing a share")
            self.shares_held -= 1
            return True
