import serial
import time
from datetime import datetime

# Configure the serial port (replace 'COM5' with your actual serial port)
ser = serial.Serial('COM5', 115200)  # For Windows
# ser = serial.Serial('/dev/ttyUSB0', 115200)  # For Linux

# Define the keyword to look for in the data
keyword = 'UID:'

# Open a file to write the data
with open("nfc_data.txt", "a") as file:
    while True:
        if ser.in_waiting:
            try:
                data = ser.readline().decode('utf-8', errors='ignore').strip()
                if keyword in data:
                    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    print(f"{current_time} - {data}")
                    file.write(f"{current_time} - {data}\n")
                    file.flush()  # Ensure the data is written to the file immediately
            except Exception as e:
                print(f"Error reading data: {e}")
        time.sleep(1)  # Short delay to avoid high CPU usage
