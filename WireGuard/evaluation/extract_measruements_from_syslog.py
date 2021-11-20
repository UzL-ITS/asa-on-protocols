import os


def extract_measurements(file_name, measurement_to_filter):
    new_file_name = file_name.replace('syslog', 'measurements') + '.txt'
    with open(file_name, 'r') as f, open(new_file_name, 'w') as fo:
        for line in f:
            if line.find(measurement_to_filter) > -1:
                measurement_result = line.split("=")[1].strip()
                fo.write(measurement_result + '\n')


for file in os.listdir():
    if file.startswith("syslog") and not file.endswith(".txt"):
        if file.find("universal_responder") > -1:
            extract_measurements(file, "response_time")
        elif file.find("iv_responder") > -1:
            extract_measurements(file, "cookie_create_time")
