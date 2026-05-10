import threading
import time

lock = threading.Lock()
thread_list = {}

def live_capture_frequency_calculation(freqlist, clearTime):
    while True:
        time.sleep(clearTime)
        with lock:
            freqlist.clear()
        
def catchFreqforExil(freqCount, num):
    if freqCount > num:
        return True

def workerCheck(freqlist, ClearTime):
    key = id(freqlist) 
    if key not in thread_list:
        with lock:    
            thread = threading.Thread(target=live_capture_frequency_calculation, args=(freqlist,ClearTime))
            thread_list[key] = thread
            thread.start()

def freqCalc(freqlist, item, countMax, clearTime):
    workerCheck(freqlist, clearTime)
    with lock:
        if item not in freqlist:
            freqlist[item] = 1
        else:
            freqlist[item] += 1
    
        print(freqlist)
        caught = catchFreqforExil(freqlist[item],countMax)
    print(f"caught: {caught}")
    return freqlist[item]

