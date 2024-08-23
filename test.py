import serial
import time

# Replace 'COM5' with your actual serial port
ser = serial.Serial('COM5', 115200)  # For Windows
# ser = serial.Serial('/dev/ttyUSB0', 115200)  # For Linux

# Open a file to write the data
with open("nfc_data.txt", "a") as file:
    while True:
        if ser.in_waiting:
            data = ser.readline().decode('utf-8').strip()
            print(data)
            file.write(data + '\n')
            file.flush()  # Ensure the data is written to the file immediately
        time.sleep(1)
