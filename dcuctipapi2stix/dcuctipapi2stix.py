"""
Copyright (c) Microsoft Corporation. All rights reserved.

Licensed under the MIT License. See LICENSE in the project root for license information.

Microsoft Digital Crimes Unit 
Cyber Threat Intelligence Program 

dcuctipapi2stix.py demonstrates how to connect to the CTIP API to download DCU CTIP data and convert to the STIX format
  - Supported datasets: CTIP Infected, CTIP C2

Install required libraries:
     run: pip install -r requirements.txt
  or run: python3 -m pip install -r requirements.txt
"""

from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import os
import argparse
from argparse import RawTextHelpFormatter
from datetime import (datetime, timezone)
from dateutil import parser # requires installation: pip install python-dateutil
import stix2.v21            # requires installation: pip install stix2
import requests             # requires installation: pip install requests
import logging
import traceback 
import json
import gzip
import time 
from http import HTTPStatus

# Program Version 
BUILD_VERSION = '2026.01.13'

# CTIP API settings
CTIP_API_BASE_URL                = 'https://api.dcuctip.com/ctip'
CTIP_API_INFECTED                = 'Infected'
CTIP_API_C2                      = 'C2'
CTIP_API_OFFSET_INIT             = 1
CTIP_API_MAX_RETRIES             = 3
CTIP_API_MAX_RETRY_DELAY_SECONDS = 10
CTIP_API_RETRY_DELAY_MULTIPLIER  = 3
CTIP_USER_AGENT                  = 'Microsoft.DCU.CTIP.dcuctipapi2stix'

# Global settings
UTC_TIMESTAMP = datetime.now(timezone.utc)
DIRECTORY_TIMESTAMP = datetime.now(timezone.utc).strftime('%Y.%m.%d_%H.%M') 
BASE_DIRECTORY = os.path.join(os.getcwd(), DIRECTORY_TIMESTAMP)
CTIP_DATA_DIRECTORY = os.path.join(BASE_DIRECTORY, 'CtipData')
STIX_DATA_DIRECTORY = os.path.join(BASE_DIRECTORY, 'StixData')
HTML_FILES_DIRECTORY = os.path.join(BASE_DIRECTORY, 'HtmlFiles')

# Global logger
LOG_FILENAME = os.path.join(BASE_DIRECTORY, f'dcuctipapi2stix_{datetime.now(timezone.utc).strftime("%Y.%m.%d_%H.%M.%S")}z.log')
log = logging.getLogger(__name__)
BASE_SPACE = '    '

#
# Class for storing CTIP API and program execution details
#
class Config:
    def __init__(self, ctipApi, subscriptionName, subscriptionKey, dataFileTimestamp, hoursAgo = 1, saveCtipDataFiles= False, saveStixDataFiles = False):
        self.CtipApi = ctipApi                      # The target CTIP API endpoint -- use constants CTIP_API_INFECTED or CTIP_API_C2
        self.SubscriptionName = subscriptionName    # A descriptive string used to name output files
        self.SubscriptionKey = subscriptionKey      # The subscription key provided by DCU to grant CTIP API access
        self.HoursAgo = hoursAgo                    # The timeframe to retrieve data from the CTIP API -- valid values are 1..72
        self.SaveCtipDataFiles = saveCtipDataFiles  # Enable (True) or disable (False) saving of CTIP data downloaded from the API to a local file
        self.SaveStixDataFiles = saveStixDataFiles  # Enable (True) or disable (False) saving of STIX data to a local file
        self.DataFileTimestamp = dataFileTimestamp  # A timestamp for consistent file naming

def ConfigureLogging():
    """
    Configures the default logging for dcuctipapi2stix.py
    """
    logging.basicConfig(format='%(asctime)s - %(message)s', 
                        level=logging.WARNING, 
                        encoding='utf-8',
                        datefmt='%Y-%m-%d %H:%M:%S', 
                        handlers=[logging.FileHandler(filename=LOG_FILENAME, encoding='utf-8', mode='w'),
                                  logging.StreamHandler()
                                 ]
                       )

def CtipApi(config: Config) -> list:
    """
    Connect to the CTIP API (Infected or C2) to download data for the desired timeframe (hoursAgo) and translate to STIX data

    Args:
        config (Config): configuration settings for CTIP API and STIX processing

    Returns:
        list: a list of STIX bundles generated from decompressed CTIP data items downloaded from the API
    """

    try:
        # Initialize totalRowCount to the supported maximum
        totalRowCount = 0 

        # Initialize offset value
        offset = CTIP_API_OFFSET_INIT

        # Counter for total downloaded rows of data
        totalDownloadedDataCount = 0

        # List of all downloaded CTIP data 
        ctipDataDownload = []

        # List of STIX bundles genereated from downloaded CTIP data 
        ctipStixData = []

        # Setup request headers
        apiHeaders = {
            'Ctip-Api-Subscription-Key': f'{config.SubscriptionKey}',
            'User-Agent': f'{CTIP_USER_AGENT}'
            }

        log.critical(f'>>>> Connecting to CTIP API: {config.CtipApi}')
        log.debug(f'          Subscription Name: {config.SubscriptionName}')
        log.debug(f'           Subscription Key: {config.SubscriptionKey}')
        log.debug(f'           Timespan (hours): {config.HoursAgo}')
        log.critical(f'     [dc: Downloaded Data Count  //  tc: Total Downloaded Count]')


        # *******************************************************************************************
        # *******************************************************************************************
        # 
        # Connect to CTIP API and download data in chunks until completed 
        # 
        # *******************************************************************************************
        # *******************************************************************************************
        while True:
            # Setup request URL
            apiUrl = f"{CTIP_API_BASE_URL}/{config.CtipApi.lower()}?hoursago={config.HoursAgo}&offset={offset}"
            log.debug(f'                    API URL: {apiUrl}')
            log.debug(f'                 Processing: {offset:07d}/{totalRowCount}')

            # Send the API request
            log.debug(f'   Sending CTIP API Request: {apiUrl}')
            # Display status to console only
            ClearStatusMessage()
            SetStatusMessage(f'Downloading data from the CTIP {config.CtipApi} API')
            apiResponse = requests.get(url=apiUrl, headers=apiHeaders)

            # Output response details
            log.debug(f'{BASE_SPACE*2}  CTIP API Response:')
            log.debug(f'{BASE_SPACE*2}             Status: {apiResponse.status_code}')
            log.debug(f'{BASE_SPACE*2}       Headers Size: {len(apiResponse.headers)}')
            log.debug(f'{BASE_SPACE*2}   Response Headers: \n{json.dumps(dict((apiResponse.headers)), indent=2)}')

            # Check for too many API requests 429 response -- if true, retry the request up to CTIP_API_MAX_RETRIES
            if apiResponse.status_code == HTTPStatus.TOO_MANY_REQUESTS.value:
                # Connection throttling to handle the 'too many requests' error
                retryAttempt = 0
                retryDelay   = CTIP_API_MAX_RETRY_DELAY_SECONDS
                # Retry the API request
                while (retryAttempt < CTIP_API_MAX_RETRIES):
                    try:
                        time.sleep(retryDelay)
                        retryAttempt += 1
                        apiResponse = requests.get(url=apiUrl, headers=apiHeaders)
                        # Check for successful connection
                        if (apiResponse.status_code == HTTPStatus.OK.value):
                            # Exit loop and process response
                            break
                    except:
                        # Multiply the delay for an exponential backoff on the next API call
                        retryDelay *= CTIP_API_RETRY_DELAY_MULTIPLIER

            # Check for successful 200 response
            if apiResponse.status_code == HTTPStatus.OK.value:
                # Extract the x-total-row-count header
                totalRowCount = int(apiResponse.headers.get('x-total-row-count'))
                if (offset == CTIP_API_OFFSET_INIT):
                    log.critical(f"{BASE_SPACE} Downloading [~{totalRowCount:07d}] data objects from the CTIP {config.CtipApi} API")

                # Decompress the downloaded chunk of GZipped data
                decompressedCtipApiData = json.loads(gzip.decompress(apiResponse.content).decode('utf-8'))

                # Capture number of data objects from the downloaded content
                downloadedDataCount = len(decompressedCtipApiData) 
                totalDownloadedDataCount += downloadedDataCount # Add downloaded count to total downloaded counter

                # Check for data to process
                if (downloadedDataCount > 0):
                    # Add downloaded data objects to the CTIP data list
                    for ctipDataObject in decompressedCtipApiData:
                        ctipDataDownload.append(ctipDataObject)

                    # dc = saved count for this iteration
                    # tc = total saved count for this API session
                    log.critical(f"{BASE_SPACE} Downloaded [dc:{downloadedDataCount:07d} // tc:{totalDownloadedDataCount:07d}] CTIP {config.CtipApi} data objects")

                    #
                    # Increment offset counter for the next iteration
                    #
                    offset += downloadedDataCount
                    log.debug(f'        downloadedDataCount: {downloadedDataCount}')
                    log.debug(f'   totalDownloadedDataCount: {totalDownloadedDataCount}')

                    # Check for overall data download completion
                    if (offset > totalRowCount):
                        # Download completed
                        log.debug(f"{BASE_SPACE} ----->> offset: {offset:07d} // totalRowCount: {totalRowCount:07d} ::> API download completed.  Exit processing. <<-----")
                        break                    
                else:
                    # Processing has completed
                    log.critical(f'{BASE_SPACE} Completed CTIP {config.CtipApi} API download')
                    break

            # Check for 400 response
            elif apiResponse.status_code == HTTPStatus.BAD_REQUEST.value:
                log.error(f'{BASE_SPACE} !!!> Encountered 400 error. Invalid value for the hoursago API parameter. Valid values are 1..72.')
                SaveErrorResponseHtml(htmlData=apiResponse.text, eventName='400error', config=config)
                break # Cannot continue -- Exit out of the loop
            # Check for 403 response
            elif apiResponse.status_code == HTTPStatus.FORBIDDEN.value:
                log.error(f'{BASE_SPACE} !!!> Encountered 403 error. Confirm that your IP address is on the CTIP API AllowList.')
                SaveErrorResponseHtml(htmlData=apiResponse.text, eventName='403error', config=config)
                break # Cannot continue -- Exit out of the loop
            else:
                # CTIP API error
                log.error(f'{BASE_SPACE} !!!> CtipApi Response Status Code: {apiResponse.status_code}')
                log.error(f'{BASE_SPACE} !!!> CtipApi Response Text:        {apiResponse.text}')
                log.error(f'{BASE_SPACE} !!!> CtipApi Response Content:     {apiResponse.content}')
                SaveErrorResponseHtml(htmlData=apiResponse.text, eventName=f'{apiResponse.status_code}error', config=config)
                break # Cannot continue -- Exit out of the loop


        # *******************************************************************************************
        # *******************************************************************************************
        # 
        # Process CTIP data to ingest into your environment 
        # 
        # *******************************************************************************************
        # *******************************************************************************************
        if (totalDownloadedDataCount > 0):
            ctipStixData = ProcessCtipData(ctipData=ctipDataDownload, config=config)


        # *******************************************************************************************
        # *******************************************************************************************
        # 
        # Save the decompressed json payload to a local file
        # 
        # *******************************************************************************************
        # *******************************************************************************************
        if (config.SaveCtipDataFiles and (len(ctipDataDownload) > 0)):
            SaveCtipDataToFile(ctipData=ctipDataDownload, config=config)


    except requests.exceptions.HTTPError as ex:
        log.error(f'{BASE_SPACE} CtipApi HTTP Error: {ex.code}')
        log.error(f'{BASE_SPACE} CtipApi HTTP Response: {ex.read()}')
    except requests.exceptions.TooManyRedirects as ex:
        log.error(f'{BASE_SPACE} CtipApi TooManyRedirects Error: {ex}')
    except requests.exceptions.SSLError as ex:
        log.error(f'{BASE_SPACE} CtipApi SSLError Error: {ex}')
    except requests.exceptions.ChunkedEncodingError as ex:
        log.error(f'{BASE_SPACE} CtipApi ChunkedEncodingError Error: {ex}')
    except requests.exceptions.InvalidURL as ex:
        log.error(f'{BASE_SPACE} CtipApi InvalidURL Error: {ex}')
    except requests.exceptions.ConnectionError as ex:
        log.error(f'{BASE_SPACE} CtipApi Connection Error: {ex}')
    except requests.exceptions.ConnectTimeout as ex:
        log.error(f'{BASE_SPACE} CtipApi ConnectTimeout Error: {ex}')
    except requests.exceptions.ReadTimeout as ex:
        log.error(f'{BASE_SPACE} CtipApi ReadTimeout Error: {ex}')
    except requests.exceptions.Timeout as ex:
        log.error(f'{BASE_SPACE} CtipApi Timeout Error: {ex}')
    except Exception as ex:
        log.error(f'{BASE_SPACE} CtipApi Error: {ex}')
        log.error('')
    finally:
        # Report total dataset objects downloaded from the API
        log.critical(f'{BASE_SPACE} Total CTIP {config.CtipApi} dataset objects downloaded: {len(ctipDataDownload)}')
        log.critical(f'{BASE_SPACE} Total CTIP {config.CtipApi} STIX bundles generated:     {len(ctipStixData)}')
        # Return the downloaded data list to CtipApi() caller
        return ctipStixData

def ProcessCtipData(ctipData: list, config: Config) -> list:
    """
    Process decompressed CTIP data from the API, Convert to STIX objects, then process as desired

    Args:
        ctipData (list): the decompressed data downloaded from the API 
        config (Config): configuration settings for CTIP API and STIX processing

    Returns:
        int: the number of CTIP data objects processed
    """

    downloadedCtipItems = len(ctipData)
    log.critical(f'{BASE_SPACE} Processing [{downloadedCtipItems}] CTIP data items')

    stixData = []

    if (config.CtipApi==CTIP_API_INFECTED):
        log.debug(f'{BASE_SPACE} Processing decompressed CTIP Infected Data')
        
        #
        # Translate CTIP Infected objects to STIX objects
        #
        itemCount = 0
        for objCtipData in ctipData:        
            # Process the instance of CTIP JSON data
            itemCount += 1

            # Display a realtime progress counter to console only
            SetStatusMessage(f'Converting CTIP Infected data to STIX objects: {itemCount} / {downloadedCtipItems}')

            try:
                # Generate STIX bundle from CTIP Infected data 
                stixCtipBundle = ConvertCtipInfectedToStix(objCtipData=objCtipData) # stix2.v21.bundle.Bundle
                stixData.append(stixCtipBundle) 

                # *******************************************************************************************
                # *******************************************************************************************
                # *******************************************************************************************
                # 
                # TODO: Add custom processing here to ingest CTIP Infected STIX data bundle (stixCtipBundle) into your environment (database, SIEM)
                log.info(f'{BASE_SPACE} [{itemCount:07d} / {downloadedCtipItems:07d}] STIX Bundle: {stixCtipBundle["id"]}')
                #
                # *******************************************************************************************
                # *******************************************************************************************
                # *******************************************************************************************

            except Exception as error:
                log.error(f'')
                log.error(f'[ {itemCount} ] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                log.error(f'[ {itemCount} ] Error processing CTIP data for object {itemCount}')
                log.error(f'[ {itemCount} ] Error:> {error}')
                log.error(f'[ {itemCount} ] This CTIP data item was not converted to a STIX object:\n{json.dumps(objCtipData, indent = 4)}')
                log.error(f'[ {itemCount} ] Call Stack:\n{traceback.format_exc().strip()}')
                log.error(f'[ {itemCount} ] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                log.error(f'')

        if (config.SaveStixDataFiles):
            SaveStixData(stixData=stixData, config=config)

    elif (config.CtipApi==CTIP_API_C2):
        log.debug(f'{BASE_SPACE} Processing decompressed CTIP C2 Data')

        #
        # Translate CTIP Infected objects to STIX objects
        #
        itemCount = 0
        for objCtipData in ctipData:        
            # Process the instance of CTIP JSON data
            itemCount += 1

            # Display a realtime progress counter to console only
            SetStatusMessage(f'Converting CTIP C2 data to STIX objects: {itemCount} / {downloadedCtipItems}')

            try:
                # Generate STIX bundle from CTIP Infected data 
                stixCtipBundle = ConvertCtipC2ToStix(objCtipData=objCtipData) # stix2.v21.bundle.Bundle
                stixData.append(stixCtipBundle) 

                # *******************************************************************************************
                # *******************************************************************************************
                # *******************************************************************************************
                # 
                # TODO: Add custom processing here to ingest CTIP C2 STIX data bundle (stixCtipBundle) into your environment (database, SIEM)
                log.info(f'{BASE_SPACE} [{itemCount:07d} / {downloadedCtipItems:07d}] STIX Bundle: {stixCtipBundle["id"]}')
                #
                # *******************************************************************************************
                # *******************************************************************************************
                # *******************************************************************************************

            except Exception as error:
                log.error(f'')
                log.error(f'[ {itemCount} ] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                log.error(f'[ {itemCount} ] Error processing CTIP data for object {itemCount}')
                log.error(f'[ {itemCount} ] Error:> {error}')
                log.error(f'[ {itemCount} ] This CTIP data item was not converted to a STIX object:\n{json.dumps(objCtipData, indent = 4)}')
                log.error(f'[ {itemCount} ] Call Stack:\n{traceback.format_exc().strip()}')
                log.error(f'[ {itemCount} ] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                log.error(f'')

        if (config.SaveStixDataFiles):
            SaveStixData(stixData=stixData, config=config)

    return stixData

def GetStixTimestamp(ctipTimestamp: str) -> datetime:
    """
    Converts a CTIP timestamp (ISO 8601) into a STIX timestamp object

    Args:
        ctipTimestamp (str): the CTIP timestamps as an ISO 8601 string in UTC timezone 

    Returns:
        datetime: the datetime object created from ctipTimestamp
    """
    objStixTimestamp = parser.isoparse(ctipTimestamp)
    return objStixTimestamp

def GetThreatConfidenceInfoInfected(ctipThreatConfidence: str) -> tuple[int, str]:
    """
    Converts a CTIP ThreatConfidence code (High/Medium/Low) into the corresponding STIX confidence scale according to the none_low_med_high_to_value scale

    Associates a CTIP ThreatConfidence code (High/Medium/Low) with a STIX Indicator Vocabulary label name

    Args:
        ctipThreatConfidence (str): the CTIP ThreatConfidence value 

    Returns:
        tuple[int, str]: a tuple containing the ThreatConfidence integer value and the associated STIX vocabulary label
    """
    if ctipThreatConfidence.lower() == "high":
        return (85,'compromised')
    elif ctipThreatConfidence.lower() == "medium":
        return (50,'malicious-activity')
    elif ctipThreatConfidence.lower() == "low":
        return (25,'anomalous-activity')
    else:
        return (0,'anomalous-activity')

def GetThreatConfidenceInfoC2(ctipThreatConfidence: str) -> tuple[int, str]:
    """
    Converts a CTIP ThreatConfidence code (High/Medium/Low) into the corresponding STIX confidence scale according to the none_low_med_high_to_value scale

    Associates a CTIP ThreatConfidence code (High/Medium/Low) with a STIX Indicator Vocabulary label name

    Args:
        ctipThreatConfidence (str): the CTIP ThreatConfidence value 

    Returns:
        tuple[int, str]: a tuple containing the ThreatConfidence integer value and the associated STIX vocabulary label
    """
    if ctipThreatConfidence.lower() == "high":
        return (85,'command-and-control')
    elif ctipThreatConfidence.lower() == "medium":
        return (50,'command-and-control')
    elif ctipThreatConfidence.lower() == "low":
        return (25,'command-and-control')
    else:
        return (0,'anomalous-activity')

def GetTlpInfo(ctipTlp: str) -> tuple[str, stix2.v21.common.MarkingDefinition]:
    """
    Converts a CTIP TLP level into the corresponding STIX TLP

    Args:
        ctipTlp (str): the CTIP TLP value 

    Returns:
        tuple[tlp_string, stix2_tlp_marking]: a tuple containing the TLP string and the associated STIX TLP marking
    """
    if ctipTlp.lower() == "red":
        return ('TLP: Red', stix2.TLP_RED)
    elif ctipTlp.lower() == "amber":
        return ('TLP: Amber', stix2.TLP_AMBER)
    elif ctipTlp.lower() == "green":
        return ('TLP: Green', stix2.TLP_GREEN)
    else:
        return ('TLP: Red', stix2.TLP_RED)

def GetHttpProtocol(port: int) -> str:
    """
    Converts a destination port number into a protocol

    Args:
        port (int): the destination port value 

    Returns:
        str: a string representing the HTTP protocol associated with port
    """
    if port is None:
        return 'unknown'
    elif not port:
        return 'unknown'
    elif port == 80:
        return 'http'
    elif port == 443:
        return 'https'
    else:
        return 'unknown'

def ConvertCtipInfectedToStix(objCtipData: dict) -> stix2.v21.bundle.Bundle:
    """
    Converts a CTIP Infected feed (continuous and summary) data (dictionary) object into a STIX Bundle object

    Args:
        objCtipData (json): a CTIP Infected JSON data object 

    Returns:
        object: a STIX Bundle object
    """

    # Convert CTIP timestamp to STIX timestamp
    objStixCtipTimestamp = GetStixTimestamp(objCtipData['DateTimeReceivedUtc'])

    # Get threat confidence info from the CTIP ThreatConfidence code
    threatConfidenceInfo = GetThreatConfidenceInfoInfected(objCtipData['ThreatConfidence'])

    # Get the TLP info
    stixCtipTlp = GetTlpInfo(objCtipData['TLP'])

    # Create a STIX Indicator object 
    # - this object contains the basic CTIP feed info
    ioc = stix2.Indicator(
        name=f"{objCtipData['Malware']}.{objCtipData['ThreatCode']}", 
        description=f"{objCtipData['Malware']} infected IP", 
        labels=['DataSet: ' + objCtipData['DataFeed'], 'SourcedFrom: ' + objCtipData['SourcedFrom'], stixCtipTlp[0], 'ThreatConfidence: ' + objCtipData['ThreatConfidence']],
        confidence=threatConfidenceInfo[0],
        indicator_types=[threatConfidenceInfo[1]],
        pattern_type="stix",
        pattern=f"[ipv4-addr:value = '{objCtipData['SourceIp']}']", 
        valid_from=objStixCtipTimestamp,
        object_marking_refs=stixCtipTlp[1]
        )

    # Create a STIX Malware object
    # - this object contains CTIP data related to the Malware family and ThreatCode
    mw = stix2.Malware(
        name=objCtipData['Malware'], 
        description=f"DCU CTIP ThreatCode: {objCtipData['ThreatCode']}", 
        is_family=True
        )

    # Create STIX IPv4Address objects -> used in the STIX NetworkTraffic object creation
    # - srcIP object contains the CTIP SourceIp
    # - dstIP object contains the CTIP DestinationIp
    srcIP = stix2.IPv4Address(value=objCtipData['SourceIp'])
    dstIP = stix2.IPv4Address(value=objCtipData['DestinationIp'])

    # Create a STIX HTTPRequestExt object -> used in the STIX NetworkTraffic object creation
    # - this object contains the CTIP HttpInfo data
    httpreq = stix2.HTTPRequestExt(
        request_method='' if not objCtipData['HttpMethod'] else objCtipData['HttpMethod'].lower(), 
        request_value='' if not objCtipData['HttpRequest'] else objCtipData['HttpRequest'], 
        request_version='' if not objCtipData['HttpVersion'] else objCtipData['HttpVersion'].lower(),
        request_header={"Host": '' if not objCtipData['HttpHost'] else objCtipData['HttpHost'], 
                        "User-Agent": '' if not objCtipData['HttpUserAgent'] else objCtipData['HttpUserAgent'], 
                        "Referer": '' if not objCtipData['HttpReferrer'] else objCtipData['HttpReferrer']}
        )

    # Create a STIX NetworkTraffic object
    # - this object contains the CTIP SourceIP+Port, DestinationIp+Port, HttpInfo (httpreq) info
    # - as well as protocol and the CTIP timestamp of the connection in STIX format
    nt = stix2.NetworkTraffic(
        src_ref=srcIP,
        src_port=objCtipData['SourcePort'],
        dst_ref=dstIP,
        dst_port=objCtipData['DestinationPort'],
        extensions={"http-request-ext": httpreq},
        start=objStixCtipTimestamp,
        protocols=[GetHttpProtocol(objCtipData['DestinationPort'])]
        )

    # Create a STIX AutonomousSystem object
    # - this object contains the CTIP SourceIp ASN info
    asn = stix2.AutonomousSystem(
        number=0 if not objCtipData['SourceIpAsnNumber'] else objCtipData['SourceIpAsnNumber'],
        name='' if not objCtipData['SourceIpAsnOrgName'] else objCtipData['SourceIpAsnOrgName']
        )

    # Create a STIX Location object
    # - this object contains the CTIP SourceIp Geolocation info

    # Normalize data when a Lat or Long is 0.0 so that the stix2.Location() call will succeed
    fLatitude = objCtipData['SourceIpLatitude']
    fLongitude = objCtipData['SourceIpLongitude']

    if str(objCtipData['SourceIpLatitude']) == '0.0':
        fLatitude = 0.0001
    if str(objCtipData['SourceIpLongitude']) == '0.0':
        fLongitude = 0.0001

    loc = stix2.Location(
        latitude=fLatitude, 
        longitude=fLongitude, 
        country='' if not objCtipData['SourceIpCountryCode'] else objCtipData['SourceIpCountryCode'], 
        region='' if not objCtipData['SourceIpRegion'] else objCtipData['SourceIpRegion'], 
        city='' if not objCtipData['SourceIpCity'] else objCtipData['SourceIpCity'] 
        )
    
    # Create STIX Note objects to handle CustomFields
    # - each object contains a CTIP CustomField for the given ThreatCode
    custom1 = stix2.Note(
        abstract=f"{objCtipData['Malware']}.{objCtipData['ThreatCode']}.CustomField1",
        content='' if not objCtipData['CustomField1'] else objCtipData['CustomField1'],
        object_refs=[ioc, nt]
        )
    custom2 = stix2.Note(
        abstract=f"{objCtipData['Malware']}.{objCtipData['ThreatCode']}.CustomField2",
        content='' if not objCtipData['CustomField2'] else objCtipData['CustomField2'],
        object_refs=[ioc, nt]
        )
    custom3 = stix2.Note(
        abstract=f"{objCtipData['Malware']}.{objCtipData['ThreatCode']}.CustomField3",
        content='' if not objCtipData['CustomField3'] else objCtipData['CustomField3'],
        object_refs=[ioc, nt]
        )
    custom4 = stix2.Note(
        abstract=f"{objCtipData['Malware']}.{objCtipData['ThreatCode']}.CustomField4",
        content='' if not objCtipData['CustomField4'] else objCtipData['CustomField4'],
        object_refs=[ioc, nt]
        )
    custom5 = stix2.Note(
        abstract=f"{objCtipData['Malware']}.{objCtipData['ThreatCode']}.CustomField5",
        content='' if not objCtipData['CustomField5'] else objCtipData['CustomField5'],
        object_refs=[ioc, nt]
        )

    # Create STIX Note objects to handle Payload field
    # - each object contains a CTIP Payload field for the given ThreatCode
    payload = stix2.Note(
        abstract=f"{objCtipData['Malware']}.{objCtipData['ThreatCode']}.Payload",
        content='' if not objCtipData['Payload'] else objCtipData['Payload'],
        object_refs=[ioc, nt]
        )

    # Create and return a bundled set of STIX objects for the converted CTIP data object
    return stix2.Bundle(ioc, mw, nt, srcIP, dstIP, asn, loc, custom1, custom2, custom3, custom4, custom5, payload)

def ConvertCtipC2ToStix(objCtipData: dict) -> stix2.v21.bundle.Bundle:
    """
    Converts a CTIP C2 feed (continuous and summary) data (dictionary) object into a STIX Bundle object

    Args:
        objCtipData (json): a CTIP C2 JSON data object 

    Returns:
        object: a STIX Bundle object
    """

    # Convert CTIP timestamp to STIX timestamp
    objStixCtipTimestamp = GetStixTimestamp(objCtipData['DateTimeReceivedUtc'])

    # Get threat confidence info from the CTIP ThreatConfidence code
    threatConfidenceInfo = GetThreatConfidenceInfoC2(objCtipData['ThreatConfidence'])

    # Get the TLP info
    stixCtipTlp = GetTlpInfo(objCtipData['TLP'])

    # Create a STIX Infrastructure object 
    # - this object contains the basic CTIP C2 feed info
    infra = stix2.Infrastructure(
        name=f"{objCtipData['Malware']}.{objCtipData['ThreatCode']}",
        description=f"{objCtipData['Malware']} C2", 
        labels=['DataSet: ' + objCtipData['DataFeed'], 'SourcedFrom: ' + objCtipData['SourcedFrom'], stixCtipTlp[0], 'ThreatConfidence: ' + objCtipData['ThreatConfidence']],
        confidence=threatConfidenceInfo[0],
        infrastructure_types=[threatConfidenceInfo[1]],
        last_seen=objStixCtipTimestamp,
        object_marking_refs=stixCtipTlp[1]
    )

    # Create a STIX Malware object
    # - this object contains CTIP data related to the Malware family and ThreatCode
    mw = stix2.Malware(
        name=objCtipData['Malware'], 
        description=f"DCU CTIP ThreatCode: {objCtipData['ThreatCode']}", 
        is_family=True
        )

    # Create STIX IPv4Address objects -> used in the STIX NetworkTraffic object creation
    # - dstIP object contains the CTIP DestinationIp
    dstIP = stix2.IPv4Address(value=objCtipData['DestinationIp'])

    # Create a STIX HTTPRequestExt object -> used in the STIX NetworkTraffic object creation
    # - this object contains the CTIP HttpInfo data
    httpreq = stix2.HTTPRequestExt(
        request_method='', 
        request_value=objCtipData['HttpRequest'], 
        request_header={"Host": objCtipData['HttpDomain']}
        )

    # Create a STIX NetworkTraffic object
    # - this object contains the CTIP DestinationIp+Port, HttpInfo (httpreq) info
    # - as well as protocol and the CTIP timestamp of the connection in STIX format
    nt = stix2.NetworkTraffic(
        dst_ref=dstIP,
        dst_port=objCtipData['DestinationPort'],
        extensions={"http-request-ext": httpreq},
        start=objStixCtipTimestamp,
        protocols=[GetHttpProtocol(objCtipData['DestinationPort'])]
        )

    # Create a STIX AutonomousSystem object
    # - this object contains the CTIP SourceIp ASN info
    asn = stix2.AutonomousSystem(
        number=0 if not objCtipData['DestinationIpAsnNumber'] else objCtipData['DestinationIpAsnNumber'],
        name='' if not objCtipData['DestinationIpAsnOrgName'] else objCtipData['DestinationIpAsnOrgName']
        )

    # Create a STIX Location object
    # - this object contains the CTIP SourceIp Geolocation info

    # Normalize data when a Lat or Long is 0.0 so that the stix2.Location() call will succeed
    fLatitude = objCtipData['DestinationIpLatitude']
    fLongitude = objCtipData['DestinationIpLongitude']

    if str(objCtipData['DestinationIpLatitude']) == '0.0':
        fLatitude = 0.0001
    if str(objCtipData['DestinationIpLongitude']) == '0.0':
        fLongitude = 0.0001

    loc = stix2.Location(
        latitude=fLatitude, 
        longitude=fLongitude, 
        country='' if not objCtipData['DestinationIpCountryCode'] else objCtipData['DestinationIpCountryCode'], 
        region='' if not objCtipData['DestinationIpRegion'] else objCtipData['DestinationIpRegion'],  
        city='' if not objCtipData['DestinationIpCity'] else objCtipData['DestinationIpCity'] 
        )

    # Create STIX Note objects to handle CustomFields
    # - each object contains a CTIP CustomField for the given ThreatCode
    custom1 = stix2.Note(
        abstract=f"{objCtipData['Malware']}.{objCtipData['ThreatCode']}.CustomField1",
        content='' if not objCtipData['CustomField1'] else objCtipData['CustomField1'],
        object_refs=[infra, nt]
        )
    custom2 = stix2.Note(
        abstract=f"{objCtipData['Malware']}.{objCtipData['ThreatCode']}.CustomField2",
        content='' if not objCtipData['CustomField2'] else objCtipData['CustomField2'],
        object_refs=[infra, nt]
        )
    custom3 = stix2.Note(
        abstract=f"{objCtipData['Malware']}.{objCtipData['ThreatCode']}.CustomField3",
        content='' if not objCtipData['CustomField3'] else objCtipData['CustomField3'],
        object_refs=[infra, nt]
        )
    custom4 = stix2.Note(
        abstract=f"{objCtipData['Malware']}.{objCtipData['ThreatCode']}.CustomField4",
        content='' if not objCtipData['CustomField4'] else objCtipData['CustomField4'],
        object_refs=[infra, nt]
        )
    custom5 = stix2.Note(
        abstract=f"{objCtipData['Malware']}.{objCtipData['ThreatCode']}.CustomField5",
        content='' if not objCtipData['CustomField5'] else objCtipData['CustomField5'],
        object_refs=[infra, nt]
        )

    try:
        # Create a STIX File object
        # - this object contains the CTIP Signatures.Sha256 hash info 
        filehash = stix2.File(
            name=objCtipData['Malware'] + ' originating malware binary',
            hashes={'SHA-256': objCtipData['Signatures']['Sha256']}
        )

        # Create and return a bundled set of STIX objects for the converted CTIP data object
        # If Sha256 length == 64, then include filehash in the bundle. Otherwise ignore.
        return stix2.Bundle(infra, mw, nt, dstIP, asn, loc, filehash, custom1, custom2, custom3, custom4, custom5)
    except:
        # Create and return a bundled set of STIX objects for the converted CTIP data object (no filehash object)
        return stix2.Bundle(infra, mw, nt, dstIP, asn, loc, custom1, custom2, custom3, custom4, custom5)

def SaveStixData(stixData: list, config: Config):
    """
    Save the CTIP data STIX Bundles to a local file for storage

    Args:
        stixData (list): the STIX data to save to the stixOutputFile file -- a list of stix2.v21.bundle.Bundle objects
        config (Config): configuration settings for CTIP API and STIX processing
    """
    log.debug(f"{BASE_SPACE} Total STIX bundles to save to file: {len(stixData)}")
    # The file to create to store STIX data
    stixOutputFile = os.path.join(STIX_DATA_DIRECTORY, f'{config.SubscriptionName}_STIX_CTIP_{config.CtipApi}_{config.DataFileTimestamp}.json')
    # Display status to console only
    SetStatusMessage(f'Saving STIX data to file: {os.path.basename(stixOutputFile)}')

    stixBundles = [json.loads(stixBundle.serialize()) for stixBundle in stixData]
    with open(stixOutputFile, 'w', encoding='utf-8') as file:
        json.dump(stixBundles, file, indent=2, ensure_ascii=False)
    
    ClearStatusMessage()
    log.critical(f"{BASE_SPACE} Saved [{len(stixData)}] CTIP {config.CtipApi} STIX data bundles to: {os.path.basename(stixOutputFile)}")

def SaveCtipDataToFile(ctipData: list, config: Config):
    """
    Create file and save content to the file

    Args:
        ctipData (list): the data to save to the file
        config (Config): configuration settings for CTIP API and STIX processing
    """

    saveFilename = os.path.join(CTIP_DATA_DIRECTORY, f'{config.SubscriptionName}_CTIP_{config.CtipApi}_{config.DataFileTimestamp}.json')
    log.info(f"{BASE_SPACE} Saving data to destination file: {saveFilename}")
    SetStatusMessage(f'Saving downloaded CTIP data to file: {os.path.basename(saveFilename)}')

    with open(saveFilename, 'w', encoding='utf-8') as saveFile:
        json.dump(ctipData, saveFile, indent=2)

    ClearStatusMessage()
    log.critical(f"{BASE_SPACE} Saved [{len(ctipData)}] CTIP {config.CtipApi} data objects to: {os.path.basename(saveFilename)}")

def SaveErrorResponseHtml(htmlData: str, eventName: str, config: Config):
    """
    Save the HTML from a error response to a local file for analysis

    Args:
        htmlData (str): the HTML content returned in the error message from the API 
        eventName (str): a custom event name used to have the saved HTML file 
        config (Config): configuration settings for CTIP API and STIX processing
    """

    # Confirm a local destination directory exists, create it if necessary
    if not os.path.exists(HTML_FILES_DIRECTORY):
        log.info(f'{BASE_SPACE} Creating HtmlFiles Directory: {HTML_FILES_DIRECTORY}')
        os.makedirs(HTML_FILES_DIRECTORY)

    destinationFilename = os.path.join(HTML_FILES_DIRECTORY, f'CTIP_{config.CtipApi}_{eventName}_{datetime.now(timezone.utc).strftime("%Y.%m.%d_%H.%M.%S")}z.html')
    log.critical(f'{BASE_SPACE} Saving API error details to: {destinationFilename}')
    with open(destinationFilename, 'w') as file:
        file.write(htmlData)

def SetStatusMessage(message: str):
    """
    Sets/updates a status message displayed on the console/terminal to the provided message

    Args:
        message (str): the message to display 
    """
    print(f'{message}', end="\r", flush=True)
    
def ClearStatusMessage():
    """
    Clears the status message displayed on the console/terminal to the provided message
    """
    SetStatusMessage(f'')
    
def FormatDateTimeYMDHMS(timestamp: datetime) -> str:
    """
    Formats a timestamp as string in the form YYYY-MM-DD HH:MM:SS

    Args:
        timestamp (datetime): the timestamp data 

    Returns:
        string: a string representation of the timestamp in the form YYYY-MM-DD HH:MM:SS
    """
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")

def GetCommandLine() -> str:
    """
    Builds the commandline that was used to launch dcuctipapi2stix.py

    Returns:
        string: a string representing the commandline used to launch dcuctipapi2stix.py
    """

    counter = 0
    strCmdLine = 'python'

    # Build command line string
    for x in sys.argv:
        log.debug(f'{counter}: {x}')
        strCmdLine = f'{strCmdLine} {x}'
        log.debug(f'{counter}: {strCmdLine}')
        counter+=1

    return strCmdLine

def main():
    #
    # Setup logging
    #

    # Confirm local logging directory exists, create it if necessary
    logPath = os.path.dirname(LOG_FILENAME)
    if not os.path.exists(logPath):
        os.makedirs(logPath)

    # Configure logger settings
    ConfigureLogging()

    #
    # Proceed with the program
    #

    log.critical('#######################################################################')
    log.critical('#######################################################################')
    log.critical('01000100 01000011 01010101 00100000 01000011 01010100 01001001 01010000')
    log.critical('01000100 01000011 01010101 00100000 01000011 01010100 01001001 01010000')
    log.critical('')
    log.critical('                         DCU CTIP API to STIX                          ')
    log.critical('')
    log.critical('                             Version  2.0                              ')
    log.critical('')
    log.critical('01000100 01000011 01010101 00100000 01000011 01010100 01001001 01010000')
    log.critical('01000100 01000011 01010101 00100000 01000011 01010100 01001001 01010000')
    log.critical('#######################################################################')
    log.critical('#######################################################################')
    log.critical('')
    log.critical(f'Build {BUILD_VERSION}')
    log.critical('')

    # Configure and Process command line arguments
    parser = argparse.ArgumentParser(description='dcuctipapi2stix - DCU CTIP API Download Utility\
	\n\nConnects to the CTIP API to download and processes DCU CTIP data for the CTIP Infected and CTIP C2 datasets.'
		, prog='dcuctipapi2stix.py'
		, formatter_class=RawTextHelpFormatter)

    parser.add_argument('--subscription-key', '-key', required=True, help=f'The CTIP API access key issued by DCU [required]')
    parser.add_argument('--subscription-name', '-sn', default='dcuctipapi2stix', help='Used to name the downloaded data file(s)\nDefault setting is "dcuctipapi2stix"')
    parser.add_argument('--hours-ago', '-ha', type=int, default=1, help='The timespan in hours to query historical CTIP API data\nRange of acceptable values is 1..72\nDefault setting is 1 hour')
    parser.add_argument('--save-ctip-data', '-sc', action='store_true', help='Flag to save downloaded CTIP data to local files \nSave to files is disabled by default')
    parser.add_argument('--save-stix-data', '-ss', action='store_true', help='Flag to save generated STIX data to local files \nSave to files is disabled by default')
    parser.add_argument('--verbose', '-v', action='store_true', help='Flag to display verbose output \nVerbose output is disabled by default')
    parser.add_argument('--debug', '-d', action='store_true', help='Flag to display debug output \nDebug output is disabled by default')
    args = parser.parse_args()

    # Set the Subscription Key API token 
    apiToken = args.subscription_key

    # Set the subscription name value 
    subscriptionName = args.subscription_name

    # Set the hoursago value 
    hoursAgo = args.hours_ago

    # Set the savectipdata flag
    saveCtipDataFiles = False
    if args.save_ctip_data:
        saveCtipDataFiles = True

    # Set the savestixdata flag
    saveStixDataFiles = False
    if args.save_stix_data:
        saveStixDataFiles = True

    # Set the verbose output flag
    if args.verbose:
        log.setLevel(logging.INFO)

    # Set the debug output flag
    if args.debug:
        log.setLevel(logging.DEBUG)

    try:
        # Confirm local directories exist, create if necessary
        if not os.path.exists(BASE_DIRECTORY):
            log.debug(f'Creating Execution Artifacts Directory: {BASE_DIRECTORY}')
            os.makedirs(BASE_DIRECTORY)
        if saveCtipDataFiles:
            if not os.path.exists(CTIP_DATA_DIRECTORY):
                log.debug(f'Creating CTIP Data Directory: {CTIP_DATA_DIRECTORY}')
                os.makedirs(CTIP_DATA_DIRECTORY)
        if saveStixDataFiles:
            if not os.path.exists(STIX_DATA_DIRECTORY):
                log.debug(f'Creating STIX Data Directory: {STIX_DATA_DIRECTORY}')
                os.makedirs(STIX_DATA_DIRECTORY)

        # Get the current UTC date/time
        startTimestampUtc = datetime.now(timezone.utc)
        startTimestampLocal = datetime.now()
        dataFileTimestamp = datetime.now(timezone.utc).strftime('%Y.%m.%d_%H.%M.%S') # Set a datetime for file naming

        # Display program configuration data
        log.critical('')
        log.debug(f'Command line:         {GetCommandLine()}')
        # log.debug(f'Subscription Key:  {apiToken}')
        log.critical(f'Subscription Name:    {subscriptionName}')
        log.critical(f'Timespan (hours):     {hoursAgo}')
        log.critical(f'Artifacts:            {BASE_DIRECTORY}')
        log.critical(f'Save CTIP Data Files: {saveCtipDataFiles}')
        log.critical(f'Save STIX Data Files: {saveStixDataFiles}')
        log.critical('') 
        log.critical('')
        log.critical(f'dcuctipapi2stix started processing at {FormatDateTimeYMDHMS(startTimestampLocal)}L / {FormatDateTimeYMDHMS(startTimestampUtc)}Z')
        log.critical('')

        # Create local storage
        ctipInfectedStixDataItems = []
        ctipC2StixDataItems = []
 
        #
        # Call the CTIP Infected API
        #
        log.critical('')
        log.critical(f'Download CTIP Infected dataset...')
        objConfigInfected = Config(ctipApi=CTIP_API_INFECTED,            # The target CTIP API endpoint -- use constant CTIP_API_INFECTED
                                   subscriptionName=subscriptionName,    # A descriptive string used to name output files
                                   subscriptionKey=apiToken,             # The subscription key provided by DCU to grant CTIP API access
                                   dataFileTimestamp=dataFileTimestamp,  # Timestamp used to name output files
                                   hoursAgo=hoursAgo,                    # The timeframe to retrieve data from the CTIP API -- valid values are 1..72
                                   saveCtipDataFiles=saveCtipDataFiles,  # Flag to control CTIP data file creation
                                   saveStixDataFiles=saveStixDataFiles)  # Flag to control STIX data file creation
                                   
        ctipInfectedStixDataItems = CtipApi(config=objConfigInfected)

        #
        # Call the CTIP C2 API
        #
        log.critical('')
        log.critical(f'Download CTIP C2 dataset...')
        objConfigC2 = Config(ctipApi=CTIP_API_C2,                  # The target CTIP API endpoint -- use constant CTIP_API_C2
                             subscriptionName=subscriptionName,    # A descriptive string used to name output files
                             subscriptionKey=apiToken,             # The subscription key provided by DCU to grant CTIP API access
                             dataFileTimestamp=dataFileTimestamp,  # Timestamp used to name output files
                             hoursAgo=hoursAgo,                    # The timeframe to retrieve data from the CTIP API -- valid values are 1..72
                             saveCtipDataFiles=saveCtipDataFiles,  # Flag to control CTIP data file creation
                             saveStixDataFiles=saveStixDataFiles)  # Flag to control STIX data file creation
                             
        ctipC2StixDataItems = CtipApi(config=objConfigC2)

        log.critical('')
        log.critical(f'Total CTIP Infected Dataset Objects Converted to STIX: {len(ctipInfectedStixDataItems)}')
        log.critical(f'Total CTIP C2 Dataset Objects Converted to STIX:       {len(ctipC2StixDataItems)}')
        log.critical('')
    except KeyboardInterrupt:
        log.error('')
        log.error('#############################################')
        log.error('dcuctipapi2stix.py aborted by user.')
        log.error('#############################################')
        sys.exit(0)
    except Exception as error:
        log.error('#############################################')
        log.error('General Error during dcuctipapi2stix.py processing.')
        log.error('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
        log.error(f'Error: {error}')
        log.error(f'Call Stack:\n{traceback.format_exc()}')
        log.error('#############################################')
    finally: 
        # Execution completed 
        endTimestampUtc = datetime.now(timezone.utc)
        endTimestampLocal = datetime.now()

        executionTime = endTimestampLocal-startTimestampLocal
        log.critical('')
        log.critical(f'dcuctipapi2stix started processing at:   {FormatDateTimeYMDHMS(startTimestampLocal)}L / {FormatDateTimeYMDHMS(startTimestampUtc)}Z')
        log.critical(f'dcuctipapi2stix completed processing at: {FormatDateTimeYMDHMS(endTimestampLocal)}L / {FormatDateTimeYMDHMS(endTimestampUtc)}Z')
        log.critical('')
        log.critical(f'dcuctipapi2stix total processing time:   {executionTime} ')
        log.critical('')
        if saveCtipDataFiles:
            log.critical(f'CTIP data files: {CTIP_DATA_DIRECTORY}')
            log.critical('')
        log.critical(f'Log file: {os.path.join(os.getcwd(), LOG_FILENAME)}')
        log.critical('')
        log.critical('######################################################')
        log.critical('dcuctipapi2stix completed.   ')
        log.critical('######################################################')

if __name__ == '__main__':
    main()
	
