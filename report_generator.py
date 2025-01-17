import requests
from pathlib import Path
import os
from dotenv import load_dotenv
import json
import hashlib
import webbrowser
import magic
import pandas as pd
import logging


# For more output during runtime, try setting urllib to DEBUG or INFO.
logging.basicConfig(level=logging.INFO)
logging.getLogger("requests").setLevel(logging.WARNING) # Set requests logging level to warning
logging.getLogger("urllib3").setLevel(logging.WARNING) # Set urllib3 logging level to warning
logger = logging.getLogger(__name__)


# Get the VirusTotal API key from environment variable
load_dotenv()
api_key = os.getenv("VIRUS_TOTAL") # https://www.virustotal.com/gui/my-apikey


def compute_sha256(file_path: Path):
    """
    Compute the SHA-256 hash of a file.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest() # returns string


def get_file_size(path):
    '''
    Get the size of a file in MB.
    '''
    file_path = Path(path)
    if file_path.is_file():
        size_in_bytes = file_path.stat().st_size
        size_in_mb = size_in_bytes / (1024 * 1024)
        size_in_mb = round(size_in_mb, 2)
        logger.info(f"File size: {size_in_mb} MB")
        return size_in_mb
    else:
        raise ValueError(f"The path {path} is not a valid file.")
    

def get_special_upload_url():
    # https://docs.virustotal.com/reference/files-upload-url
    url = "https://www.virustotal.com/api/v3/files/upload_url"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)
    response_json = response.json()
    special_upload_url = response_json["data"]
    logger.debug(special_upload_url)
    return special_upload_url


def scan_file(file: Path, special_upload_url: str = None):
    '''
    https://docs.virustotal.com/reference/files-scan
    TODO: add support for url
    '''
    if special_upload_url is None:
        # for files under 32MB
        url = "https://www.virustotal.com/api/v3/files"
    else:
        # for files between 32MB and 200MB (technically up to 600MB)
        url = special_upload_url

    # Assign MIME type based on file name/extension
    mime_type = magic.from_file(str(file), mime=True)

    # Prepare file tuple: (filename, fileobj, content_type)
    files = {
        "file": (
            file.name,          # For the filename in the uploaded form field
            open(file, "rb"),   # The actual file object
            mime_type           # The MIME type of the file
        )
    }

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    response = requests.post(url, files=files, headers=headers)
    response_json = response.json()

    # Save the scan report to a file
    report_path = Path(f"scans/{file.name}.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as report_file:
        json.dump(response_json, report_file, indent=4)

    logger.info(f"Scan data saved to {report_path}.")
    return response


def get_report(file: Path):
    '''
    https://docs.virustotal.com/reference/file-info
    Provide hash to get report.
    '''
    hash = compute_sha256(file)
    
    url = f"https://www.virustotal.com/api/v3/files/{hash}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
        }
    
    response = requests.get(url, headers=headers)
    response_json = response.json()

    report_path = Path(f"reports/{file.name}.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)

    with open(report_path, "w") as report_file:
        json.dump(response_json, report_file, indent=4)

    logger.info(f"Report data saved to {report_path}.")

    return response


def open_report(file_path: Path):
    file_hash = compute_sha256(file_path)
    url = f'https://www.virustotal.com/gui/file/{file_hash}'
    webbrowser.open(url)


def create_or_update_dataframe(file_path: Path, file_hash: str, file_size: float, csv_path: str = "reports/virus_total_data.csv"):
    """
    Create or update a dataframe with columns for filepath, hash, and report url.
    If the dataframe already exists, it keeps the headers and appends the new data.
    """

    report_url = f'https://www.virustotal.com/gui/file/{file_hash}'
    data = {
        "report_url": [report_url],
        "datetime": [pd.Timestamp.now().isoformat()],
        "sha256": [file_hash],
        "size_mb": [file_size],
        "filepath": [str(file_path)],
    }

    new_df = pd.DataFrame(data)

    if Path(csv_path).exists():
        existing_df = pd.read_csv(csv_path)
        updated_df = pd.concat([existing_df, new_df], ignore_index=True)
    else:
        updated_df = new_df

    updated_df.to_csv(csv_path, index=False)
    logger.debug(f"Dataframe updated and saved to {csv_path}")


def main(file: str):
    '''
    # For files smaller than 32MB, use the POST endpoint.
    # For files larger than 32MB but not exceeding 200MB, use the special upload URL first. 
    # For files larger than 200MBs up to 650MB, it is suggested to upload inner files first.
    '''
    file_path = Path(file)
    file_size = get_file_size(file_path)
    file_hash = compute_sha256(file_path)

    if file_size <= 32:
        scan_file(file_path, None)
    else:
        special_upload_url = get_special_upload_url()
        scan_file(file_path, special_upload_url)
    
    get_report(file_path)

    create_or_update_dataframe(file_path, file_hash, file_size)

    open_report(file_path)


if __name__ == "__main__":
    files_to_scan = [
        r"C:\Users\NathanTafelsky\Downloads\Soil_biology.pdf", # Add the path to file here, full path recommended
    ]

    for file in files_to_scan:
        main(file)


