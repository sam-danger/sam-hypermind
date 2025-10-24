import random, datetime

def read_all():
    data = {
        "temperature": round(random.uniform(20.0, 45.0), 2),
        "humidity": round(random.uniform(30.0, 70.0), 2),
        "light": round(random.uniform(100, 800), 2),
        "noise": round(random.uniform(20, 80), 2),
        "timestamp": datetime.datetime.now().isoformat()
    }
    return data
