"""
This script is designed to manage digital certificates in a git repository.
It keeps track of certificates that are close to the expiration date and 
creates JIRA tickets for them.
All relevant certificates are stored in an output text file.

Original idea and working prototype by: N. Affolter
Redesign, extension and implementation by: M. Kuchelmeister
"""

import os
import zipfile
import shutil
import subprocess
import json
import configparser
from xml.dom import minidom
from OpenSSL.crypto import load_certificate
from OpenSSL.crypto import FILETYPE_PEM
from datetime import datetime, date, timedelta
from dateutil import relativedelta
from collections import defaultdict


import logging

logging.basicConfig(level=logging.DEBUG)


def log_function_call(function):
    def wrapper(*args, **kwargs):
        logging.info(f"Entering {function.__name__}")
        result = function(*args, **kwargs)
        logging.info(f"Exiting {function.__name__}")
        return result

    return wrapper


@log_function_call
def is_git_directory(path="."):
    """
    Check if the provided path is a git repository.

    Args:
    path (str): The path to the directory to check.
    Defaults to the current directory '.'.

    Returns:
    bool: True if the directory is a git repository, False otherwise.
    """
    try:
        return (
            subprocess.call(
                ["git", "-C", path, "status"],
                stderr=subprocess.STDOUT,
                stdout=open(os.devnull, "w"),
            )
            == 0
        )
    except FileNotFoundError:
        raise FileNotFoundError("Git is not found on this system.")


@log_function_call
def find_repo_older(path=os.path.abspath(os.getcwd())):
    """
    Find the directory with all the content from the 7.7 policies
    in the provided path.

    Args:
    path (str): The path to the directory to check. Defaults to the current
    working directory.

    Returns:
    str: The path to the directory with all the content from the 7.7 policies.
    Returns an empty string if no such directory is found.
    """
    for pathy in os.listdir(path):
        cur = os.path.join(path, pathy)
        if is_git_directory(cur) and "Configurations_7.7" in os.listdir(cur):
            return os.path.join(cur, "Configurations_7.7")
    return ""


def find_repo(version="", path=os.path.abspath(os.getcwd())):
    """
    Find the directory with all the content from the provided version policies
    in the given path.

    Args:
    version (str): The version of the policies. If not provided, the maximum
    version is used. Defaults to an empty string.
    path (str): The path to the directory to check. Defaults to the current
    working directory.

    Returns:
    str: The path to the directory with all the content from the specified
    version policies. Returns an empty string if no such directory is found.
    """
    for pathy in os.listdir(path):
        cur = os.path.join(path, pathy)
        if is_git_directory(cur):
            content_list = os.listdir(cur)
            if not version:
                version = max(x for x in content_list)
            if version in content_list:
                return os.path.join(cur, version, "policies")
    return ""


@log_function_call
def find_versions(path=os.path.abspath(os.getcwd())):
    """
    Find all versions in the provided path.

    Args:
    path (str): The path to the directory to check. Defaults to the current
    working directory.

    Returns:
    list: A list of all version strings found in the directory, sorted in
    descending order.
    """
    versions = []
    for pathy in os.listdir(path):
        cur = os.path.join(path, pathy)
        if is_git_directory(cur):
            for sub_dir in os.listdir(cur):
                if os.path.isdir(os.path.join(cur, sub_dir)) and "git" not in sub_dir:
                    versions.append(sub_dir)
    versions.sort(reverse=True)
    return versions


@log_function_call
def parse_cert(cert_file):
    """
    Parse a certificate file and extract information.

    Args:
    cert_file (str): The path to the certificate file.

    Returns:
    list: A list containing the certificate creation date, the run out date,
    the issuer, and the serial number.
    """
    try:
        with open(cert_file, "rb") as f:
            cert_pem = f.read()
            x509 = load_certificate(FILETYPE_PEM, cert_pem)
            date_format = "%Y%m%d%H%M%SZ"
            encoding = "ascii"
            encod = "utf-8"
            not_before = datetime.strptime(
                x509.get_notBefore().decode(encoding), date_format
            ) + timedelta(hours=1)
            not_after = datetime.strptime(
                x509.get_notAfter().decode(encoding), date_format
            ) + timedelta(hours=1)
            issuer = ", ".join(
                [
                    x[0].decode(encod) + "=" + x[1].decode(encod)
                    for x in x509.get_subject().get_components()
                ]
            )
            serial_number = hex(x509.get_serial_number())[2:].upper()
            return [not_before, not_after, issuer, serial_number]
    except (FileNotFoundError, ValueError):
        raise


@log_function_call
def delete_files_in_folder(folder_path):
    """
    Delete all files in a directory.

    Args:
    folder_path (str): The path to the directory.
    """
    if not os.path.isdir(folder_path):
        raise ValueError(f"{folder_path} is not a directory.")

    for file_object in os.listdir(folder_path):
        file_object_path = os.path.join(folder_path, file_object)
        if os.path.isfile(file_object_path) or os.path.islink(file_object_path):
            os.unlink(file_object_path)
        else:
            shutil.rmtree(file_object_path)


@log_function_call
def delete_folder(folder_path):
    """
    Delete a directory.

    Args:
    folder_path (str): The path to the directory.
    """
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)


@log_function_call
def create_pem_file(content, path, file_name="cert_file.pem"):
    """
    Creates a PEM file with a given content.

    Parameters:
    content (str): The string content to be written into the PEM file.
    path (str): The directory path where the PEM file will be created.
    file_name (str, optional): The name of the PEM file.
    Default is 'cert_file.pem'.
    """
    full_path = os.path.join(path, file_name)
    content = content.replace("\n", "").replace("\r", "")
    with open(full_path, "w") as f:
        f.write("-----BEGIN CERTIFICATE-----\n")
        f.write(content + "\n")
        f.write("-----END CERTIFICATE-----")


@log_function_call
def get_all_folder_paths(git_conf_path):
    """
    Returns a dictionary with all the given paths. The returned object is a
    dictionary with the policies as keys containing a dictionary with
    subpolicies as keys containing a list with all the environments.

    Parameters:
    git_conf_path (str): The root directory to start looking for policies
    and environments.

    Returns:
    dict: A dictionary with nested structure representing the policy,
    subpolicy and environment relationships.
    """
    if os.path.isdir(git_conf_path):
        return {
            policy: {
                sub_policy: [
                    file
                    for file in os.listdir(
                        os.path.join(git_conf_path, policy, sub_policy)
                    )
                    if file.endswith(".env")
                ]
                for sub_policy in os.listdir(os.path.join(git_conf_path, policy))
            }
            for policy in os.listdir(git_conf_path)
            if not policy.startswith("API-")
        }
    else:
        return {}


@log_function_call
def unzip(file_path, store_path):
    """
    Unzips a file to a given path.

    Parameters:
    file_path (str): The path of the zip file to be unzipped.
    store_path (str): The directory path where the unzipped files will be stored.
    """
    if os.path.isfile(file_path) and zipfile.is_zipfile(file_path):
        with zipfile.ZipFile(file_path, "r") as zip_ref:
            zip_ref.extractall(store_path)
    else:
        print(f"Invalid file or path: {file_path}")


@log_function_call
def xml_path_for_Cert(folder_path):
    """
    Returns the path to the CertStore.xml file for a given path to an environment file.

    Parameters:
    folder_path (str): The path to the directory containing the CertStore.xml file.

    Returns:
    str: The full path of the CertStore.xml file.
    """
    try:
        sub_folder = [x for x in os.listdir(folder_path) if not x.startswith("META")][0]
        cert_file = [
            x
            for x in os.listdir(os.path.join(folder_path, sub_folder))
            if x.startswith("Cert") and x.endswith(".xml")
        ][0]
        return os.path.join(folder_path, sub_folder, cert_file)
    except (IndexError, FileNotFoundError) as e:
        print(f"Error: {e}")
        return None


@log_function_call
def is_within_three_months(end_date):
    """
    Checks if a given date is within 3 months from the current date.

    Parameters:
    end_date (datetime): The end date to be checked.

    Returns:
    bool: True if the date is within 3 months from now, False otherwise.
    """
    today = date.today()
    end_date = end_date.date()
    delta = relativedelta.relativedelta(end_date, today)
    return delta.years == 0 and delta.months <= 2 and delta.days >= 0


@log_function_call
def parse_xml_for_certs(xml_file_path, temp_folder):
    """
    Returns all the content from a Certificate contained in a given
    CertStore.xml file.

    Parameters:
    xml_file_path (str): The path to the CertStore.xml file.
    temp_folder (str): The temporary directory where PEM files will be created.

    Returns:
    list: A list containing the not_before, not_after, issuer, and
    serial_number information for each certificate.
    """
    container = []
    if os.path.isfile(xml_file_path):
        file = minidom.parse(xml_file_path)
        models = file.getElementsByTagName("entity")
        for m in models:
            if m.attributes["type"].value == "Certificate":
                for i in range(len(m.childNodes)):
                    try:
                        if m.childNodes[i].attributes["name"].value == "content":
                            content = m.childNodes[i].childNodes[0].firstChild.nodeValue
                            create_pem_file(content, temp_folder)
                            not_before, not_after, issuer, serial_number = parse_cert(
                                os.path.join(temp_folder, "cert_file.pem")
                            )
                            if is_within_three_months(not_after):
                                container.append(
                                    [not_before, not_after, issuer, serial_number]
                                )
                            break
                    except:
                        continue
    else:
        print(f"Invalid file: {xml_file_path}")
    return container


@log_function_call
def path_builder(root, policy, sub_policy, env_file):
    """
    Constructs a directory path from the provided components.

    Parameters:
    root (str): The root directory.
    policy (str): The policy directory.
    sub_policy (str): The subpolicy directory.
    env_file (str): The environment file.

    Returns:
    str: The constructed path string.
    """
    return os.path.join(root, policy, sub_policy, env_file)


@log_function_call
def month_converter(month):
    """
    Converts the number of a month to the matching name in German.

    Parameters:
    month (int): The month number from 1 (January) to 12 (December).

    Returns:
    str: The month name in German, or 'Invalid month' if the
    month number is out of range.
    """
    months = {
        1: "Januar",
        2: "Februar",
        3: "März",
        4: "April",
        5: "Mai",
        6: "Juni",
        7: "Juli",
        8: "August",
        9: "September",
        10: "Oktober",
        11: "November",
        12: "Dezember",
    }
    return months.get(month, "Invalid month")


@log_function_call
def database_updater(Policy, environment_content, database="database_certs.json"):
    """
    Stores all the certificates, for which a JIRA ticket was created, such that
    no double tickets will be generated.

    Parameters:
    Policy (str): The policy for the certificate.
    environment_content (dict): A dictionary containing the certificate details.
    database (str, optional): The path to the JSON file where the certificates
    data are stored. Default is 'database_certs.json'.
    """
    try:
        with open(database, "r") as f:
            data_all = json.load(f)
    except FileNotFoundError:
        data_all = {}

    data = data_all.get(Policy, {})
    for env, certs in environment_content.items():
        for cert in certs:
            not_before, not_after, issuer, serial_number = cert
            month = month_converter(int(not_after.month))
            year = not_after.year
            date = f"{month}/{year}"
            data.setdefault(date, {}).setdefault(env, []).append(serial_number)

    data_all[Policy] = data
    with open(database, "w") as f:
        json.dump(data_all, f, indent=4)


@log_function_call
def create_JIRA_tickets(
    Policy,
    environment_content,
    database="database_certs.json",
    filename="data_JIRA.json",
):
    """
    Takes all the certificates from one Policy and splits them up based on the
    month they run out. Then it calls the Json modifier function and then
    the send curl function.

    Parameters:
    Policy (str): The policy for the certificate.
    environment_content (dict): A dictionary containing the certificate details.
    database (str, optional): The path to the JSON file where the
    certificates data are stored. Default is 'database_certs.json'.
    filename (str, optional): The name of the JSON file to be created.
    Default is 'data_JIRA.json'.
    """
    with open(database, "r") as f:
        data = json.load(f)

    months_cert = defaultdict(lambda: defaultdict(list))
    for env, certs in environment_content.items():
        for cert in certs:
            not_before, not_after, issuer, serial_number = cert
            month = not_after.month
            year = not_after.year
            date = f"{month_converter(month)}/{year}"
            if (
                Policy not in data
                or date not in data[Policy]
                or env not in data[Policy][date]
                or serial_number not in data[Policy][date][env]
            ):
                months_cert[month][env].append([not_after, serial_number, issuer])
    print(months_cert)
    # for month, env_certs in months_cert.items():
    #     new_filename = modify_json(Policy, month, env_certs, filename)
    #     send_curl(data_path=new_filename)


@log_function_call
def modify_json(Policy, month, given, filename="data_JIRA.json"):
    """
    Modifies the default Json file to add the certificates for a given
    month to the Summary and description.

    Parameters:
    Policy (str): The policy for the certificate.
    month (int): The expiry month of the certificate.
    given (dict): A dictionary containing the certificate details.
    filename (str, optional): The name of the JSON file to be created.
    Default is 'data_JIRA.json'.

    Returns:
    str: The path of the new JSON file.
    """
    with open(filename, "r") as f:
        data = json.load(f)

    data["fields"]["summary"] += f"{Policy} - {month_converter(month)}"
    data["fields"]["description"] += f"{Policy}:\n\n"
    for env, certs in given.items():
        data["fields"]["description"] += f"{env}\t:\n"
        for not_after, serial_number, issuer in certs:
            data["fields"][
                "description"
            ] += f"\t\t * EndDate: {not_after}\tSerialID: {serial_number}\tIssuer: {issuer}\n"

    new_filename = "data_JIRA_altered.json"
    if os.path.exists(new_filename):
        os.remove(new_filename)
    with open(new_filename, "w") as f:
        json.dump(data, f, indent=4)

    return new_filename


@log_function_call
def send_curl(data_path="data_JIRA.json"):
    """
    Send a curl to the Jira rest API with a given Json file.

    Parameters:
    data_path (str, optional): The path to the JSON file containing the data
    to be sent. Default is 'data_JIRA.json'.
    """
    command = [
        "curl",
        "-D-",
        "-u",
        "<ID>:<PW>",
        "-X",
        "POST",
        "--data",
        f"@{data_path}",
        "-H",
        "Content-Type: application/json",
        "https://jira.ucc/rest/api/2/issue/",
    ]
    subprocess.run(command, check=True)


@log_function_call
def delete_file_in_directory(directory, file_name):
    """
    Deletes a specific file within a provided directory.
    Creates the directory if it does not already exist.
    """
    directory_path = os.path.join(directory, file_name)
    if os.path.exists(directory_path):
        os.unlink(directory_path)


@log_function_call
def create_output_file(local_git_path, output_file="output.txt", zones=set()):
    """
    Writes certificate contents from a local git path to an output file.
    If an entry in the git path is already in zones, it is skipped.
    """
    temp_folder = "tempy_folder"
    output_folder = "output_folder"
    entries = get_all_folder_paths(local_git_path)
    output_file_path = os.path.join(output_folder, output_file)

    with open(output_file_path, "a") as f:
        holder = []
        for entry in entries:
            if entry in zones:
                continue
            holder.append(entry + ":\n")
            zones.add(entry)
            for ent in entries[entry]:
                holder.append("\t" + ent + ":\n")
                environment_content = {}
                for e in entries[entry][ent]:
                    holder.append("\t\t" + e + ":\n")
                    path = path_builder(local_git_path, entry, ent, e)
                    delete_folder(temp_folder)
                    unzip(path, temp_folder)
                    xml_path = xml_path_for_Cert(temp_folder)
                    container = parse_xml_for_certs(xml_path, temp_folder)
                    Policy, Environment = e.split(".")[0].split("_")
                    environment_content[Environment] = container
                    if container:
                        f.write("".join(holder))
                        holder = []
                    else:
                        holder = holder[:-1]
                    for cont in container:
                        f.write(
                            "\t\t\t"
                            + "EndDate: "
                            + str(cont[1])
                            + "\tSerialID: "
                            + str(cont[3])
                            + "\tIssuer: "
                            + cont[2]
                            + "\n"
                        )
                create_JIRA_tickets(Policy, environment_content)
                database_updater(Policy, environment_content)
                if holder and holder[-1] == "\t" + ent + ":\n":
                    holder = holder[:-1]
            if holder and holder[-1] == entry + ":\n":
                holder = holder[:-1]


@log_function_call
def send_file(mail_to, file="output_folder/output.txt"):
    """
    Sends an email with a specific file attached to a given email address.
    """
    subprocess.run(
        ["mutt", "-s", "Certificates that need updating", mail_to, "<", file],
        check=True,
    )


@log_function_call
def read_config(file="configurations.ini", path=None):
    """
    Loads configurations from a given .ini file in a specified path.
    If no path is provided, it defaults to the current working directory.
    """
    path = path or os.getcwd()
    config = configparser.ConfigParser()
    config.read(os.path.join(path, file))
    return config


@log_function_call
def main():
    """
    The main execution function that sets up necessary variables,
    deletes the output file, creates a new output file with certificate information
    and sends the output file to a specified email address.
    """
    # Load configurations
    config = read_config()

    # Extract necessary variables from config
    mail_to = config["Settings"]["email"]
    version = config["Settings"]["version"]

    # Find all versions
    versions = find_versions()

    # Delete previous output file
    delete_file_in_directory()

    # Initialize zones set
    zones = set([])

    # Loop through versions, create an output file for each, and send it via email
    while versions:
        version = versions.pop(0)
        create_output_file(find_repo(version=version), zones=zones)
    # send_file(mail_to)


if __name__ == "__main__":
    main()
