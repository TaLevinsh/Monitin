import os
import hashlib
from datetime import datetime
import requests


def file_to_hash(path):
    """Calculate the MD5 hash of a file."""
    try:
        with open(path, 'rb') as file:
            hash_md5 = hashlib.md5()
            hash_md5.update(file.read())
        return hash_md5.hexdigest()
    except FileNotFoundError:
        print(f"Error: File {path} not found.")
        return None


def one_file():
    """Handle hashing and virus checking for a single file."""
    file_path = input('Insert the file path -> ').strip()
    if not os.path.isfile(file_path):
        print(f"Error: {file_path} is not a valid file.")
        return

    file_hash = file_to_hash(file_path)
    if file_hash:
        print(f"The file MD5 is: {file_hash}")


def get_report(file_hash):
    """Query VirusTotal API for a hash report."""
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        print("Error: VirusTotal API key is not set.")
        return None

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': file_hash}
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error querying VirusTotal: {e}")
        return None


def parse_report(file_hash):
    """Parse the VirusTotal report for a given file hash."""
    data = get_report(file_hash)
    if not data:
        return 0.0

    if 'verbose_msg' in data and 'Invalid resource' in data['verbose_msg']:
        return 0.9  # Arbitrary score for invalid resources

    positives = data.get('positives', 0)
    total = data.get('total', 1)  # Avoid division by zero
    return positives / total


def all_files():
    """Process all files in a directory, calculate hashes, and query VirusTotal."""
    directory_path = input('Insert the directory path -> ').strip()
    if not os.path.isdir(directory_path):
        print(f"Error: {directory_path} is not a valid directory.")
        return

    dict_files = {}
    for root, _, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                    is_executable = file_content[:2] == b"MZ"
            except (OSError, IOError):
                print(f"Error reading file: {file_path}")
                continue

            file_hash = file_to_hash(file_path)
            if not file_hash:
                continue

            modification_time = datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
            rate = parse_report(file_hash)
            file_type = 'Executable' if is_executable else 'Not Executable'

            dict_files[filename] = (file_hash, modification_time, file_type, rate)
            print(f"File: {filename}\n"
                  f"  Type: {file_type}\n"
                  f"  MD5: {file_hash}\n"
                  f"  Modified: {modification_time}\n"
                  f"  VirusTotal Rate: {rate}\n")

    return dict_files


def main():
    print('The HASHER')
    print('-' * 20)
    try:
        opt = int(input('[1] Calculate hash for a file\n'
                        '[2] Calculate hashes for all files under a directory\n'
                        '> ').strip())
        if opt == 1:
            one_file()
        elif opt == 2:
            all_files()
        else:
            print("Invalid selection!")
    except ValueError:
        print("Error: Please enter a valid number.")


if __name__ == '__main__':
    main()
