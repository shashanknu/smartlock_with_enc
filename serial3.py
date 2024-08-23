import serial
import datetime

def read_nfc_uid(port='COM5', baudrate=115200, filename='nfc_uids.txt'):
    ser = serial.Serial(port, baudrate, timeout=1)
    try:
        with open(filename, 'a') as file:  # Open the file in append mode
            while True:
                if ser.in_waiting > 0:
                    line = ser.readline().decode('utf-8').strip()
                    if "UID Value:" in line:
                        uid = line.split(":")[1].strip()
                        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        file.write(f"{timestamp} - UID: {uid}\n")
                        print(f"{timestamp} - UID: {uid}")
    except KeyboardInterrupt:
        print("Exiting...")
    finally:
        ser.close()

if __name__ == "__main__":
    read_nfc_uid()
