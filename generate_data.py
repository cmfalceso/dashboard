import pandas as pd
import random
import time
from datetime import datetime, timedelta

devices = {
    "Household_1": ["Camera_1", "Thermostat", "LightBulb"],
    "Household_2": ["DoorLock", "Camera_2", "SmartTV"],
    "Household_3": ["WeatherSensor", "Camera_3", "Router"],
    "Household_4": ["LightBulb_2", "Thermostat_2", "Camera_4"],
    "Household_5": ["DoorLock_2", "SmartTV_2", "Router_2"]
}

monitor_devices = ["RasPi", "VM1", "VM2", "VM3", "VM4", "VM5"]

infection_probability = {
    "Household_1": 0.10,
    "Household_2": 0.30,
    "Household_3": 0.50,
    "Household_4": 0.70,
    "Household_5": 0.90
}

attack_types = ["Mirai", "DoS", "Scanning", "Ransomware"]

def generate_batch():
    rows = []
    start_time = datetime.now()

    # Household IoT devices
    for i in range(20):
        household = random.choice(list(devices.keys()))
        device = random.choice(devices[household])
        infected = random.random() < infection_probability[household]

        rows.append({
            "timestamp": (start_time + timedelta(seconds=i)).strftime("%H:%M:%S"),
            "household": household,
            "device": device,
            "attack_type": random.choice(attack_types) if infected else "Normal",
            "prediction": "malware" if infected else "benign",
            "confidence": round(random.uniform(0.85, 0.99), 2),
            "cpu_usage": None,
            "ram_usage": None
        })

    # Monitored devices (RasPi + VMs)
    for device in monitor_devices:
        is_under_attack = random.random() < 0.2
        cpu = round(random.uniform(60, 95) if is_under_attack else random.uniform(10, 50), 1)
        ram = round(random.uniform(55, 90) if is_under_attack else random.uniform(20, 55), 1)
        infected = is_under_attack and random.random() < 0.5

        rows.append({
            "timestamp": start_time.strftime("%H:%M:%S"),
            "household": "Monitor",
            "device": device,
            "attack_type": random.choice(attack_types) if infected else "Normal",
            "prediction": "malware" if infected else "benign",
            "confidence": round(random.uniform(0.85, 0.99), 2),
            "cpu_usage": cpu,
            "ram_usage": ram
        })

    pd.DataFrame(rows).to_csv("detections.csv", mode='a', header=False, index=False)
    print(f"[{start_time.strftime('%H:%M:%S')}] Batch generated.")

# Clears the CSV on every fresh run of the generator
with open("detections.csv", "w") as f:
    f.write("timestamp,household,device,attack_type,prediction,confidence,cpu_usage,ram_usage\n")

while True:
    generate_batch()
    time.sleep(1)
