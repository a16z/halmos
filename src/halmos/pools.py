from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

# defined as globals so that they can be imported from anywhere but instantiated only once
process_pool = ProcessPoolExecutor()
thread_pool = ThreadPoolExecutor()
