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


def is_git_directory(path = '.'):
    """
    Returns True if the current directory is a GIT Repository and False otherwise.
    """
    return subprocess.call(['git', '-C', path, 'status'], stderr=subprocess.STDOUT, stdout = open(os.devnull, 'w')) == 0


def find_repo_older(path = os.path.abspath(os.getcwd())):
    """
    Returns the path to the folder with all the content from the 7.7 policies.
    """
    for pathy in os.listdir(path):
        cur = path + '/' + pathy
        if is_git_directory(cur) and 'Configurations_7.7' in os.listdir(cur):
            return cur + '/' + 'Configurations_7.7'
    return ''


def find_repo(version = '',path = os.path.abspath(os.getcwd())):
    """
    Returns the path to the folder with all the content from the 7.7 policies.
    """
    for pathy in os.listdir(path):
        cur = path + '/' + pathy
        if is_git_directory(cur):
            if not version:
                version =max([x for x in os.walk(cur)][0][1])
            if version in os.listdir(cur):
                return cur + '/' + version +'/' + 'policies'
    return ''


def find_versions(path = os.path.abspath(os.getcwd())):
    versions = []
    for pathy in os.listdir(path):
        cur = path + '/' + pathy
        if is_git_directory(cur):
            for x in os.listdir(cur):
            # for root,dirs, files in os.walk(cur):
            #     print(root,dirs,files)
            #     for dir in dirs:
            #         print(dir)
                if os.path.isdir(cur+'/'+x) and not 'git' in x:
                    versions.append(x)
    versions.sort(reverse=True)
    return versions


def parse_cert(cert_file):
    """
    Returns the extracted information from the pem file. Currently it extracts the certificate creation date and the run out date as well as the issuer and serial number.
    """
    with open(cert_file, 'rb+') as f:
        cert_pem = f.read()
        f.close()
        x509 = load_certificate(FILETYPE_PEM, cert_pem)
        date_format, encoding, encod = "%Y%m%d%H%M%SZ", "ascii", 'utf-8'
        not_before = datetime.strptime(x509.get_notBefore().decode(encoding), date_format)+ timedelta(hours=1)
        not_after = datetime.strptime(x509.get_notAfter().decode(encoding), date_format)+ timedelta(hours=1)
        issuer = ', '.join([x[0].decode(encod)+'='+x[1].decode(encod) for x in x509.get_subject().get_components()])
        serial_number = hex(x509.get_serial_number())[2:].upper()
        return [not_before,not_after,issuer,serial_number]


def delete_files_in_folder(folder_path):
    """
    Deletes all the files in a folder for given path.
    """
    for file_object in os.listdir(folder_path):
        file_object_path = os.path.join(folder_path, file_object)
        if os.path.isfile(file_object_path) or os.path.islink(file_object_path):
            os.unlink(file_object_path)
        else:
            shutil.rmtree(file_object_path)


def delete_folder(folder_path):
    """
    Deletes a folder for a given path.
    """
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)


def create_pem_file(content,path,file_name='cert_file.pem'):
    """
    Creates a pem file with a given content.
    """
    with open(path + '/' + file_name, 'w') as f:
        f.write('-----BEGIN CERTIFICATE-----')
        f.write('\n')
        content = content.replace('\n','')
        content = content.replace('\r','')
        f.write(content)
        f.write('\n')
        f.write('-----END CERTIFICATE-----')


def get_all_folder_paths(git_conf_path):
    """
    Returns a dictionary with all the given paths. The returned object is a dictionary with the policies as keys cntaining a dictionary with subpolicies as keys containing a list with all the environments.
    """
    return { x:{y:[file for file in os.listdir(git_conf_path+'/'+x+'/'+y) if file.endswith('.env')] for y in os.listdir(git_conf_path +'/'+x)} for x in os.listdir(git_conf_path) if not x.startswith('API-')}


def unzip(file_path,store_path):
    """
    Unzip a folder for a given path.
    """
    with zipfile.ZipFile(file_path, 'r') as zip_ref:
        zip_ref.extractall(store_path)


def xml_path_for_Cert(folder_path):
    """
    Returns the path to the CertStore.xml file for a given path to an environment file.
    """
    return os.path.join(folder_path, [x for x in os.listdir(folder_path) if not x.startswith('META')][0], [x for x in os.listdir(os.path.join(folder_path, [x for x in os.listdir(folder_path) if not x.startswith('META')][0]))if x.startswith('Cert') and x.endswith('.xml') ][0])


def less_than_month(end_date):
    """
    Returns True if the date lies within 3 months from now else False.
    """
    today = datetime.strptime(str(date.today()), "%Y-%m-%d")
    end_date = end_date.date()
    delta = relativedelta.relativedelta(end_date, today)
    return delta.years==0 and delta.months<=2 and delta.days>=0


def parse_xml_for_certs(xml_file_path,temp_folder):
    """
    Returns all the content (see in parse_cert) from a Certificate contained in a given CertStore.xml file (given by path). Stores information for extraction in temp_folder.
    """
    container = []
    file = minidom.parse(xml_file_path)
    models = file.getElementsByTagName('entity')
    for m in models:
        if m.attributes['type'].value =='Certificate':
            for i in range(len(m.childNodes)):
                try:
                    if m.childNodes[i].attributes['name'].value =='content':
                        content = m.childNodes[i].childNodes[0].firstChild.nodeValue
                        create_pem_file(content,temp_folder)
                        not_before,not_after,issuer,serial_number=parse_cert(temp_folder + '/' + 'cert_file.pem')
                        if less_than_month(not_after):
                            container.append([not_before,not_after,issuer,serial_number])
                        break
                except:
                    continue
    return container


def path_builder(root,policy,sub_policy,env_file):
    """
    Returns the path to a file for given folders that contain the file and the file name.
    """
    return root+'/'+policy+'/'+sub_policy+'/'+env_file


def month_converter(month):
    """
    Converts the number of a month to the matching name.
    """
    months = [
    (1, 'Januar'),
    (2, 'Februar'),
    (3, 'Maerz'),
    (4, 'April'),
    (5, 'Mai'),
    (6, 'Juni'),
    (7, 'Juli'),
    (8, 'August'),
    (9, 'September'),
    (10, 'Oktober'),
    (11, 'November'),
    (12, 'Dezember'),
    ]
    return months[month-1][1]


def database_updater(Policy,environment_content,database='database_certs.json'):
    """
    Stores all the certificates, for which a JIRA ticket was created, such that no double tickets will be generated.
    """
    with open(database, 'r') as f:
        data_all = json.load(f)
        if Policy in data_all:
            data = data_all[Policy]
        else: data = {}
        for env in environment_content:
            for cert in environment_content[env]:
                not_before,not_after,issuer,serial_number = cert
                month = month_converter(int(not_after.month))
                year = not_after.year
                date = month + '/' + str(year)
                if not date in data:
                    data[date]={env:[serial_number]}
                else:
                    if not env in data[date]:
                        data[date][env]=[serial_number]
                    elif serial_number not in data[date][env]:
                        data[date][env].append(serial_number)
        if data:
            data_all[Policy] = data
    os.remove(database)
    with open(database, 'w') as f:
        json.dump(data_all, f, indent=4)
    return


def create_JIRA_tickets(Policy,environment_content,database='database_certs.json',filename='data_JIRA.json'):
    """
    Takes all the certificates from one Policy and splits them up based on the month they run out. Then it calls the Json modifier function and then the send curl function.
    """
    with open(database, 'r') as f:
        data = json.load(f)
        months_cert = defaultdict(lambda: defaultdict(list))
        for env in environment_content:
            for cert in environment_content[env]:
                not_before,not_after,issuer,serial_number = cert
                month = not_after.month
                year = not_after.year
                date = month_converter(int(not_after.month)) + '/' + str(year)
                if Policy not in data or date not in data[Policy] or env not in data[Policy][date] or serial_number not in data[Policy][date][env]:
                    months_cert[month][env].append([not_after,serial_number,issuer])
    for month in months_cert:
        new_filename = modifiy_json(Policy,month,months_cert[month])
        send_curl(data_path=new_filename)
    return


def modifiy_json(Policy,month,given,filename='data_JIRA.json'):
    """
    Modifies the default Json file to add the certificates for a given month to the Summary and description.
    """
    with open(filename, 'r') as f:
        data = json.load(f)
        data['fields']['summary']+=Policy+' - '+month_converter(month)
        data['fields']['description']+=Policy+':\n\n'
        for env in given:
            data['fields']['description']+=env+'\t:\n'
            for cert in given[env]:
                not_after,serial_number,issuer = cert
                data['fields']['description']+='\t\t * '+'EndDate: '+str(not_after)+'\tSerialID: '+str(serial_number)+'\tIssuer: '+issuer+'\n'
    new_filename = 'data_JIRA_altered.json'
    if os.path.exists(new_filename):
        os.remove(new_filename)
    with open(new_filename, 'w') as f:
        json.dump(data, f, indent=4)
    return new_filename


def send_curl(data_path='data_JIRA.json'):
    """
    Send a curl to the Jira rest API with a given Json file.
    """
    command = f'curl \
        -D- \
        -u <ID>:<PW> \
        -X POST  \
        --data @{data_path} \
        -H "Content-Type: application/json" \
        https://jira.ucc/rest/api/2/issue/'
    os.system(command)


def create_output_file_old(local_git_path,output_file = 'output.txt'):
    """
    Stores all the content from the Certificates in a text file.
    """
    temp_folder= 'tempy_folder'
    output_folder = 'output_folder'
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    elif os.path.exists(output_folder + '/' + output_file):
        os.unlink(output_folder + '/' + output_file)
    entries = get_all_folder_paths(local_git_path)
    with open(output_folder + '/' + output_file, 'w') as f:
        holder = []
        for entry in entries:
            holder.append(entry + ':\n')
            for ent in entries[entry]:
                holder.append('\t'+ent+':\n')
                environment_content = {}
                for e in entries[entry][ent]:
                    holder.append('\t\t'+e+':\n')
                    path = path_builder(local_git_path,entry,ent,e)
                    delete_folder(temp_folder)
                    unzip(path,temp_folder)
                    xml_path = xml_path_for_Cert(temp_folder)
                    container = parse_xml_for_certs(xml_path,temp_folder)
                    Policy, Environment = e.split('.')[0].split('_')
                    environment_content[Environment]=container
                    if container:
                        f.write(''.join(holder))
                       holder = []
                    else:
                        holder=holder[:-1]
                    for cont in container:
                        f.write('\t\t\t'+'EndDate: '+str(cont[1])+'\tSerialID: '+str(cont[3])+'\tIssuer: '+cont[2]+'\n')
                create_JIRA_tickets(Policy,environment_content)
                database_updater(Policy,environment_content)
                if holder and holder[-1]=='\t'+ent+':\n':
                    holder=holder[:-1]
            if holder and holder[-1]==entry + ':\n':
                holder=holder[:-1]


def delete_output_file(output_file = 'output.txt'):
    output_folder = 'output_folder'
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    elif os.path.exists(output_folder + '/' + output_file):
        os.unlink(output_folder + '/' + output_file)
    print('Output file deleted')


def create_output_file(local_git_path,output_file = 'output.txt'):
    """
    Stores all the content from the Certificates in a text file.
    """
    global zones
    temp_folder= 'tempy_folder'
    output_folder = 'output_folder'
    entries = get_all_folder_paths(local_git_path)
    with open(output_folder + '/' + output_file, 'a') as f:
        holder = []
       for entry in entries:
            if entry in zones: continue
            holder.append(entry + ':\n')
            zones.add(entry)
            for ent in entries[entry]:
                holder.append('\t'+ent+':\n')
                environment_content = {}
                for e in entries[entry][ent]:
                    holder.append('\t\t'+e+':\n')
                    path = path_builder(local_git_path,entry,ent,e)
                    delete_folder(temp_folder)
                    unzip(path,temp_folder)
                    xml_path = xml_path_for_Cert(temp_folder)
                    container = parse_xml_for_certs(xml_path,temp_folder)
                    Policy, Environment = e.split('.')[0].split('_')
                    environment_content[Environment]=container
                    if container:
                        f.write(''.join(holder))
                        holder = []
                    else:
                        holder=holder[:-1]
                    for cont in container:
                        f.write('\t\t\t'+'EndDate: '+str(cont[1])+'\tSerialID: '+str(cont[3])+'\tIssuer: '+cont[2]+'\n')
                create_JIRA_tickets(Policy,environment_content)
                database_updater(Policy,environment_content)
                if holder and holder[-1]=='\t'+ent+':\n':
                    holder=holder[:-1]
            if holder and holder[-1]==entry + ':\n':
                holder=holder[:-1]


def send_file(mail_to,file = "output_folder/output.txt"):
    """
    Send an email to a given mail address and a given text file.
    """
    os.system(f'mutt -s "Certificates that need updating" {mail_to} < {file}')


def read_config(file = 'configurations.ini',path = os.path.abspath(os.getcwd())):
    """
    Load the configurations needed to run the code
    """
    if path.split('/')[-1]=='Utils':
        path = '/'.join(path.split('/')[:-1])
    config = configparser.ConfigParser()
    config.read(path+'/'+file)
    return config


"""
Variables that need to be set
"""
config = read_config()
mail_to = config['Settings']['email']
version = config['Settings']['version']
versions = find_versions()
"""
Run
"""
delete_output_file()
zones = set([])
while versions:
    version = versions.pop(0)
    create_output_file(find_repo(version=version))
send_file(mail_to)