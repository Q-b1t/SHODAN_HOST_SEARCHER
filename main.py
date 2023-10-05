import numpy as np
import pandas as pd
import shodan
from shodan.cli.helpers import get_api_key
import configparser
from termcolor import colored
from argparse import ArgumentParser,Namespace
import json
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from auxiliary_modules.shodan_search import *


if __name__ == '__main__':
    # instance command line parser
    parser = ArgumentParser()
    # add cli arguments
    parser.add_argument("-i","--input_file",help="Input file containing the hostsnames (default: \"hosts.txt\")",type=str,default="hosts.txt",nargs="?")
    parser.add_argument("-o","--output_file",help="Name of the output file the hostnames will be exported to (default: \"host_table\")",type=str,default="host_table",nargs="?")
    parser.add_argument("-c","--config_file",help="Configuration file contianing a Shodan API key (default: \"shodan_conf.cfg\")",type=str,default="shodan_conf.cfg",nargs="?")
    parser.add_argument("-v","--verbose",help="Whether to output into the console information about the script's progress or not",type=bool,default=False,nargs="?")
    parser.add_argument("-f","--output_format",help="It can be either \"excel\" or \"csv\" (default: \"excel\")",type=str,default="excel",nargs="?")

    args: Namespace = parser.parse_args()
    input_file = args.input_file
    output_file = args.output_file
    config_file = args.config_file
    verbose = args.verbose
    output_format = args.output_format
    print(output_format)

    SHODAN_API_KEY = get_api_key(config_file=config_file,verbose=verbose)
    # instance shodan api client
    api = shodan.Shodan(SHODAN_API_KEY)

    # validate the input file
    validate_name(input_file,verbose=verbose)

    # validate output fole
    validate_output_file(output_file)

    # get the list of hosts
    host_list = read_text_file(input_file)

    # get the list of hosts
    responses = make_shodan_requests(api=api,host_list=host_list,verbose=verbose)

    # get information
    basic_data_list,metadata_list,vulnerabilities_list,reference_list = extract_shodan_response_data(responses=responses)

    # make a table out of general data (single and expanded)
    basic_data_table = build_expanded_data_table(basic_data_list)
    metadata_table = pd.DataFrame(metadata_list)
    general_table = clean_merge(metadata_table,basic_data_table,["ip_str"])

    # make a table of vulnerabilities general data and the expanded references
    vulnerability_data_table = build_expanded_data_table(vulnerabilities_list)
    reference_table = build_expanded_data_table(reference_list)
    vulnerability_data_table.drop("references",axis=1,inplace=True)
    vulnerability_data_table = clean_merge(vulnerability_data_table,reference_table,["vulns"])

    # make a table containing all the parsed data
    shodan_compilation = clean_merge(general_table,vulnerability_data_table,["vulns"])
    
    save_table(parsed_table=shodan_compilation,save_path=output_file,output_format=output_format,verbose=verbose)








