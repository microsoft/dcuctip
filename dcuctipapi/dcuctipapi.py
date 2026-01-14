"""
Copyright (c) Microsoft Corporation. All rights reserved.

Licensed under the MIT License. See LICENSE in the project root for license information.

Microsoft Digital Crimes Unit 
Cyber Threat Intelligence Program 

dcuctipapi.py demonstrates how to connect to the CTIP API to download and process DCU CTIP data
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
import logging
import traceback 
import json
import gzip
import time 
from http import HTTPStatus
import requests  # requires installation: pip install requests

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
CTIP_USER_AGENT                  = 'Microsoft.DCU.CTIP.dcuctipapi'

# Global settings
UTC_TIMESTAMP = datetime.now(timezone.utc)
DIRECTORY_TIMESTAMP = datetime.now(timezone.utc).strftime('%Y.%m.%d_%H.%M') 
BASE_DIRECTORY = os.path.join(os.getcwd(), DIRECTORY_TIMESTAMP)
CTIP_DATA_DIRECTORY = os.path.join(BASE_DIRECTORY, 'CtipData')
HTML_FILES_DIRECTORY = os.path.join(BASE_DIRECTORY, 'HtmlFiles')

# Global logger
LOG_FILENAME = os.path.join(BASE_DIRECTORY, f'dcuctipapi_{datetime.now(timezone.utc).strftime("%Y.%m.%d_%H.%M.%S")}z.log')
log = logging.getLogger(__name__)
BASE_SPACE = '    '

#
# Class for storing CTIP API and program execution details
#
class Config:
    def __init__(self, ctipApi, subscriptionName, subscriptionKey, dataFileTimestamp, hoursAgo = 1, saveCtipDataFiles= False):
        self.CtipApi = ctipApi                      # The target CTIP API endpoint -- use constants CTIP_API_INFECTED or CTIP_API_C2
        self.SubscriptionName = subscriptionName    # A descriptive string used to name output files
        self.SubscriptionKey = subscriptionKey      # The subscription key provided by DCU to grant CTIP API access
        self.HoursAgo = hoursAgo                    # The timeframe to retrieve data from the CTIP API -- valid values are 1..72
        self.SaveCtipDataFiles = saveCtipDataFiles  # Enable (True) or disable (False) saving of CTIP data downloaded from the API to a local file
        self.DataFileTimestamp = dataFileTimestamp  # A timestamp for consistent file naming

def ConfigureLogging():
    """
    Configures the default logging for dcuctipapi.py
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
    Connect to the CTIP API (Infected or C2) to download data for the desired timeframe (hoursAgo)

    Args:
        config (Config): configuration settings for CTIP API  

    Returns:
        list: a list of decompressed CTIP data items downloaded from the API
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
            ProcessCtipData(ctipData=ctipDataDownload, config=config)


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
        # Return the downloaded data list to CtipApi() caller
        return ctipDataDownload

def ProcessCtipData(ctipData: list, config: Config) -> int:
    """
    Process decompressed CTIP data from the API as desired

    Args:
        ctipData (list): the decompressed data downloaded from the API 
        config (Config): configuration settings for CTIP API

    Returns:
        int: the number of CTIP data objects processed
    """

    downloadedCtipItems = len(ctipData)
    log.critical(f'{BASE_SPACE} Processing [{downloadedCtipItems}] CTIP data items')

    if (config.CtipApi==CTIP_API_INFECTED):
        log.debug(f'{BASE_SPACE} Processing decompressed CTIP Infected Data')
        
        itemCount = 0
        for objCtipData in ctipData:        
            # Process the instance of CTIP JSON data
            itemCount += 1

            # Display a realtime progress counter to console only
            SetStatusMessage(f'Processing CTIP Infected data object: {itemCount} / {downloadedCtipItems}')

            # *******************************************************************************************
            # *******************************************************************************************
            # *******************************************************************************************
            # 
            # TODO: Add custom processing here to ingest CTIP Infected data (objCtipData) into your environment (database, SIEM)
            log.info(f'{BASE_SPACE} [{itemCount:07d} / {downloadedCtipItems:07d}] Malware: {objCtipData["Malware"]} // ThreatCode: {objCtipData["ThreatCode"]} // ThreatConfidence: {objCtipData["ThreatConfidence"]} // Source IP: {objCtipData["SourceIp"]}')
            #
            # *******************************************************************************************
            # *******************************************************************************************
            # *******************************************************************************************

    elif (config.CtipApi==CTIP_API_C2):
        log.debug(f'{BASE_SPACE} Processing decompressed CTIP C2 Data')

        itemCount = 0
        for objCtipData in ctipData:        
            # Process the instance of CTIP JSON data
            itemCount += 1

            # Display a realtime progress counter to console only
            SetStatusMessage(f'Processing CTIP C2 data object: {itemCount} / {downloadedCtipItems}')

            # *******************************************************************************************
            # *******************************************************************************************
            # *******************************************************************************************
            # 
            # TODO: Add custom processing here to ingest CTIP C2 data (objCtipData) into your environment (database, SIEM)
            log.info(f'{BASE_SPACE} [{itemCount:07d} / {downloadedCtipItems:07d}] Malware: {objCtipData["Malware"]} // ThreatCode: {objCtipData["ThreatCode"]} // ThreatConfidence: {objCtipData["ThreatConfidence"]} // Destination IP: {objCtipData["DestinationIp"]}')
            #
            # *******************************************************************************************
            # *******************************************************************************************
            # *******************************************************************************************


    return downloadedCtipItems

def SaveCtipDataToFile(ctipData: list, config: Config):
    """
    Create file and save content to the file

    Args:
        ctipData (list): the data to save to the file
        config (Config): configuration settings for CTIP API
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
        config (Config): configuration settings for CTIP API
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
    Builds the commandline that was used to launch dcuctipapi.py

    Returns:
        string: a string representing the commandline used to launch dcuctipapi.py
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
    log.critical('                             DCU CTIP API                              ')
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
    parser = argparse.ArgumentParser(description='dcuctipapi - DCU CTIP API Download Utility\
	\n\nConnects to the CTIP API to download and processes DCU CTIP data for the CTIP Infected and CTIP C2 datasets.'
		, prog='dcuctipapi.py'
		, formatter_class=RawTextHelpFormatter)

    parser.add_argument('--subscription-key', '-key', required=True, help=f'The CTIP API access key issued by DCU [required]')
    parser.add_argument('--subscription-name', '-sn', default='dcuctipapi', help='Used to name the downloaded data file(s)\nDefault setting is "dcuctipapi"')
    parser.add_argument('--hours-ago', '-ha', type=int, default=1, help='The timespan in hours to query historical CTIP API data\nRange of acceptable values is 1..72\nDefault setting is 1 hour')
    parser.add_argument('--save-ctip-data', '-save', action='store_true', help='Flag to save downloaded CTIP data to local files \nSave to files is disabled by default')
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
        log.critical('') 
        log.critical('')
        log.critical(f'dcuctipapi started processing at {FormatDateTimeYMDHMS(startTimestampLocal)}L / {FormatDateTimeYMDHMS(startTimestampUtc)}Z')
        log.critical('')

        # Create local storage
        ctipInfectedDataItems = []
        ctipC2DataItems = []
 
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
                                   saveCtipDataFiles=saveCtipDataFiles)  # Flag to control CTIP data file creation
                                   
        ctipInfectedDataItems = CtipApi(config=objConfigInfected)

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
                             saveCtipDataFiles=saveCtipDataFiles)  # Flag to control CTIP data file creation
                             
        ctipC2DataItems = CtipApi(config=objConfigC2)

        log.critical('')
        log.critical(f'Total CTIP Infected Dataset Objects: {len(ctipInfectedDataItems)}')
        log.critical(f'Total CTIP C2 Dataset Objects:       {len(ctipC2DataItems)}')
        log.critical('')
    except KeyboardInterrupt:
        log.error('')
        log.error('#############################################')
        log.error('dcuctipapi.py aborted by user.')
        log.error('#############################################')
        sys.exit(0)
    except Exception as error:
        log.error('#############################################')
        log.error('General Error during dcuctipapi.py processing.')
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
        log.critical(f'dcuctipapi started processing at:   {FormatDateTimeYMDHMS(startTimestampLocal)}L / {FormatDateTimeYMDHMS(startTimestampUtc)}Z')
        log.critical(f'dcuctipapi completed processing at: {FormatDateTimeYMDHMS(endTimestampLocal)}L / {FormatDateTimeYMDHMS(endTimestampUtc)}Z')
        log.critical('')
        log.critical(f'dcuctipapi total processing time:   {executionTime} ')
        log.critical('')
        if saveCtipDataFiles:
            log.critical(f'CTIP data files: {CTIP_DATA_DIRECTORY}')
            log.critical('')
        log.critical(f'Log file: {os.path.join(os.getcwd(), LOG_FILENAME)}')
        log.critical('')
        log.critical('######################################################')
        log.critical('dcuctipapi completed.   ')
        log.critical('######################################################')

if __name__ == '__main__':
    main()
	
