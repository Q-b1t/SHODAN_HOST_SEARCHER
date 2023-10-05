import shodan
import pandas as pd
import os
import configparser
from termcolor import colored

def read_text_file(filename):
    with open(filename,"r",encoding="utf-8") as f:
        lines = f.readlines()
    f.close()
    return [line.strip() for line in lines]

def get_api_key(config_file,verbose):
    # parse the configuration file
    validate_config_file(config_file=config_file)
    config = configparser.ConfigParser()
    config.read(config_file)
    assert config['API_KEY']["shodan"] != "" ,colored(f"[-] The configuration file does not contain an API key.","red")
    if verbose:
        print(colored("[+] Shodan API key found.","green"))
    return config['API_KEY']["shodan"]

def validate_config_file(config_file):
    assert  os.path.isfile(config_file),colored(f"[-] Configuration file {config_file} does not seem to exist. Please check for any errors.","red")

def validate_output_file(output_file):
    # validate if outfile file contains no extentions and if the save path exist
    assert "xlsx" not in output_file or  "csv" not in output_file, colored(f"[-] The output file should only be limited to the name. Please ommit the extention.","red")
    if output_file.find("/") != -1 or output_file.find("\\") != -1:
        path = os.path.dirname(output_file)
        assert os.path.exists(path=path), colored(f"The output file path {path} does not seem to exist.","red")

def validate_name(filename,verbose):
    # validate if the input file exist and if it contains an allowed extention
    assert  os.path.isfile(filename),colored(f"[-] Specified file {filename} does not seem to exist. Please check for any errors.","red")
    extention = filename.split(".")[-1]
    assert  extention == "txt" ,colored(f"[-] Specified file {filename} is not in an allowed format (txt).","red")
    if verbose:
        print(colored(f"[+] File {filename} found.","green"))


def get_listed_samples(shodan_sample,keys_list):
  return {key:pd.Series(shodan_sample[key]) for key in keys_list}

def append_merging_factors(listed_table,shodan_sample,merging_factors):
  for factor in merging_factors:
    listed_table[factor] = shodan_sample[factor]

def clean_merge(l_table,r_table,merge_params):
  l_table = l_table.merge(r_table,how="outer",on=merge_params)
  for col in l_table.columns:
    if col[-2:] == "_x":
      other = col.replace("_x","_y")
      l_table[col].update(l_table[other])
      l_table.drop(other,axis=1,inplace=True)
      l_table.rename(columns={col: col[:-2]},inplace=True)
    return l_table

  # validate if the shodan dump actually contains vulnerability information
def contains_samples(shodan_sample):
  return "vulns" in shodan_sample.keys()

# extract the metadata to merge based on it.
def extract_primary_metadata(shodan_sample,keys=["ip_str","last_update","org","asn","city","isp","os",],fetch_vulns=False):
  metadata = {key:shodan_sample[key] for key in keys if key in shodan_sample.keys()}
  if fetch_vulns:
    return pd.Series(metadata),shodan_sample["vulns"]
  else:
    return pd.Series(metadata)

def get_vulnerability_metadata(shodan_sample):
  return shodan_sample["data"][0]["vulns"]

def append_name_vuln_metadata(vuln_metadata):
  for key,value in vuln_metadata.items():
    value["vulns"] = key


# extract the advanced metadata regarding vulnerabilities
def extract_vulnerabilities(vuln_metadata,vuln_list):
  #vuln_metadata = shodan_sample["data"][0]["vulns"]
  vuln_parsed_list = list()
  for vuln in vuln_list:
    if vuln in vuln_metadata.keys():
      vuln_dump = dict()
      vuln_data = vuln_metadata[vuln]
      vuln_dump.update(vuln_data)
      vuln_parsed_list.append(vuln_dump)
    else:
      continue
  return vuln_parsed_list

# receives a list of individual dataframes corresponding to a single expanded sample and builds the entire expanded table
def build_expanded_data_table(series_list):
  tables_list = [pd.DataFrame(data) for data in series_list]
  expanded_table = tables_list[0]
  for table in tables_list:
    expanded_table = pd.concat([expanded_table,table])
  return expanded_table


def make_shodan_requests(api,host_list,verbose):
    hosts_info = list()
    for h in host_list:
        try:
            res = api.host(h)
            hosts_info.append(res)
            if verbose:
               print(colored(f"[+] Found information on host: {h}","green"))

        except:
            print(colored(f"[-] Host {h} info could not be retrieved.","red"))
    return hosts_info


def extract_shodan_response_data(responses):
  basic_data_list,metadata_list,vulnerabilities_list,reference_list = list(),list(),list(),list()
  for res in responses:
    if contains_samples(res):
      basic_data = get_listed_samples(res,["ports","vulns","domains","hostnames"]) # listed fields
      append_merging_factors(basic_data,res,["ip_str"]) #  add the same merging factor
      metadata,vuln_list = extract_primary_metadata(res,fetch_vulns=True) # extract general single listed metadata
      vuln_metadata = get_vulnerability_metadata(res) # extract vulnerabilities raw dicitonary
      append_name_vuln_metadata(vuln_metadata)
      vulnerabilities = extract_vulnerabilities(vuln_metadata,vuln_list) # get a list of dictionaries for each vulnerability
      for vuln_example in vulnerabilities: # expand the references of each vulnerability
        vuln_references = get_listed_samples(vuln_example,["references"])
        append_merging_factors(vuln_references,vuln_example,["vulns"])
        reference_list.append(vuln_references)
      basic_data_list.append(basic_data)
      metadata_list.append(metadata)
      vulnerabilities_list.append(vulnerabilities)
    else:
      basic_data = get_listed_samples(res,["ports","domains","hostnames"])
      append_merging_factors(basic_data,res,["ip_str"])
      metadata = extract_primary_metadata(res)
      basic_data_list.append(basic_data)
      metadata_list.append(metadata)
  return basic_data_list,metadata_list,vulnerabilities_list,reference_list


def save_table(parsed_table,save_path,output_format,verbose):
    """
    Inputs: 
        - parsed_table: A processed pandas dataframe.
        - save_path: The to which the table will be saved as an excel book.
    """
    if output_format == "csv":
        filename = save_path + "." + "csv"
        parsed_table.to_csv(filename,index = False)
    else:
        filename = save_path + "." + "xlsx"
        parsed_table.to_excel(filename, index=False)
         
    if verbose:
        print(colored(f"[+] Exporting the results to {filename}.","green"))