import psutil, platform, datetime

def get_status():
    temp = 0
    try:
        temps = psutil.sensors_temperatures()
        if "coretemp" in temps:
            temp = temps["coretemp"][0].current
        elif "cpu_thermal" in temps:
            temp = temps["cpu_thermal"][0].current
    except Exception:
        pass

    return {
        "cpu": psutil.cpu_percent(interval=0.5),
        "ram": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage("/").percent,
        "temp": round(temp, 1),
        "os": platform.system(),
        "timestamp": datetime.datetime.now().isoformat(),
    }
