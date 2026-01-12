"""
Copyright (c) Microsoft Corporation. All rights reserved.

Licensed under the MIT License. See LICENSE in the project root for license information.

Microsoft Digital Crimes Unit 
Cyber Threat Intelligence Program 

dcuctiptsfapi.py demonstrates how to connect to the CTIP API to download and process DCU CTIP data
  - Supported datasets: CTIP TSF

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
from io import BytesIO
from http import HTTPStatus
import requests  # requires installation: pip install requests

# Program Version 
BUILD_VERSION = '2026.01.05'

# CTIP API settings
CTIP_API_BASE_URL                = 'https://api.dcuctip.com/fraud' 
CTIP_API_FRAUD_TSF               = 'TSFReportAScam' 
CTIP_API_OFFSET_INIT             = 1
CTIP_API_MAX_RETRIES             = 3
CTIP_API_MAX_RETRY_DELAY_SECONDS = 10
CTIP_API_RETRY_DELAY_MULTIPLIER  = 3
CTIP_USER_AGENT                  = 'Microsoft.DCU.CTIP.dcuctiptsfapi'

# Global settings
UTC_TIMESTAMP = datetime.now(timezone.utc)
DIRECTORY_TIMESTAMP = datetime.now(timezone.utc).strftime('%Y.%m.%d_%H.%M') 
BASE_DIRECTORY = os.path.join(os.getcwd(), DIRECTORY_TIMESTAMP)
CTIP_DATA_DIRECTORY = os.path.join(BASE_DIRECTORY, 'CtipData')
HTML_FILES_DIRECTORY = os.path.join(BASE_DIRECTORY, 'HtmlFiles')

# Global logger
LOG_FILENAME = os.path.join(BASE_DIRECTORY, f'dcuctiptsfapi_{datetime.now(timezone.utc).strftime("%Y.%m.%d_%H.%M.%S")}z.log')
log = logging.getLogger(__name__)
BASE_SPACE = '    '

def ConfigureLogging():
    """
    Configures the default logging for dcuctiptsfapi.py
    """
    logging.basicConfig(format='%(asctime)s - %(message)s', 
                        level=logging.WARNING, 
                        encoding='utf-8',
                        datefmt='%Y-%m-%d %H:%M:%S', 
                        handlers=[logging.FileHandler(filename=LOG_FILENAME, encoding='utf-8', mode='w'),
                                  logging.StreamHandler()
                                 ]
                       )

def CtipFraudApi(ctipApi: str, subscriptionName: str, subscriptionKey: str, daysAgo: int, saveCtipDataFiles: bool) -> int:
    """
    Connect to the CTIP API (TSF) to download data for the desired timeframe (daysAgo)

    Args:
        ctipApi (str): the target CTIP API endpoint - use constant CTIP_API_FRAUD_TSF
        subscriptionName (str): a descriptive string used to name output files
        subscriptionKey (str): the subscription key provided by DCU to grant CTIP API access
        daysAgo (int): the timeframe to retrieve data from the CTIP API; valid values are 1..180

    Returns:
        int: the total number of CTIP data items downloaded from the API
    """

    try:
        # Set a datetime for file naming
        ctipDataFileDateTime = datetime.now(timezone.utc).strftime('%Y.%m.%d_%H.%M.%S') 

        # Initialize totalRowCount to the supported maximum
        totalRowCount = 0 

        # Initialize offset value
        offset = CTIP_API_OFFSET_INIT

        # Counter for total downloaded rows of data
        totalDownloadedDataCount = 0

        # Counter for total files created
        gzFileCount = 0

        # Setup request headers
        apiHeaders = {
            'Ctip-Api-Subscription-Key': f'{subscriptionKey}',
            'User-Agent': f'{CTIP_USER_AGENT}'
            }

        log.critical(f'>>>> Connecting to CTIP API: {ctipApi}')
        log.info(f'          Subscription Name: {subscriptionName}')
        log.info(f'           Subscription Key: {subscriptionKey}')
        log.info(f'            Timespan (days): {daysAgo}')
        log.critical(f'     [dc: Downloaded Data Count  //  tc: Total Downloaded Count]')

        #
        # Connect to CTIP API and download data in chunks
        #
        while True:
            # Setup request URL
            apiUrl = f"{CTIP_API_BASE_URL}/{ctipApi.lower()}?daysago={daysAgo}&offset={offset}"
            log.critical(f'                    API URL: {apiUrl}')
            log.debug(f'                   Headers: {apiHeaders}')
            log.debug(f'                Processing: {offset:07d}/{totalRowCount}')

            # Send the API request
            log.debug(f'   Sending CTIP API Request: {apiUrl}')
            # Display status to console only
            SetStatusMessage(f'Downloading data from the CTIP {ctipApi} API')
            apiResponse = requests.get(url=apiUrl, headers=apiHeaders)

            # Output response details
            log.info(f'{BASE_SPACE*2}  CTIP API Response:')
            log.info(f'{BASE_SPACE*2}             Status: {apiResponse.status_code}')
            log.info(f'{BASE_SPACE*2}       Headers Size: {len(apiResponse.headers)}')
            log.info(f'{BASE_SPACE*2}   Response Headers: \n{json.dumps(dict((apiResponse.headers)), indent=2)}')

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
                    log.critical(f"{BASE_SPACE} Downloading [~{totalRowCount:07d}] rows of data from the CTIP {ctipApi} API")

                # Determine number of data rows from the downloaded content
                log.info(f'{BASE_SPACE} Determine the number of data rows downloaded')
                downloadedDataCount = GetDownloadedDataCount(apiResponse.content)
                totalDownloadedDataCount += downloadedDataCount # Add downloaded count to total downloaded counter

                # Check for data to process
                if (downloadedDataCount > 0):
                    #
                    # Save Downloaded CTIP data to a local file
                    #
                    log.info(f"{BASE_SPACE} Downloaded [dc:{downloadedDataCount:07d} // tc:{totalDownloadedDataCount:07d}] rows of CTIP {ctipApi} data")

                    # Save the GZip compressed json payload to a local file
                    if (saveCtipDataFiles):
                        gzFileCount += 1
                        gzFilename = os.path.join(CTIP_DATA_DIRECTORY, f'{subscriptionName}_CTIP_{ctipApi}_{ctipDataFileDateTime}_{gzFileCount:03d}.json.gz')
                        log.info(f"{BASE_SPACE} Target destination file: {gzFilename}")
                        WriteDataToFile(gzFilename, apiResponse.content)

                        # Determine number of data rows saved
                        log.info(f'{BASE_SPACE} Determine the number of data rows saved to file')
                        savedDataCount = GetSavedDataCount(gzFilename)
                        # dc = saved count for this iteration
                        # tc = total saved count for this API session
                        log.critical(f"{BASE_SPACE} Saved [dc:{savedDataCount:07d} // tc:{totalDownloadedDataCount:07d}] rows of CTIP {ctipApi} data to: {os.path.basename(gzFilename)}")

                    # *******************************************************************************************
                    # *******************************************************************************************
                    # 
                    # Ingest CTIP data into your environment 
                    # 
                    # *******************************************************************************************
                    # *******************************************************************************************
                    UncompressAndProcessCtipData(data=apiResponse.content, ctipDataset=ctipApi)

                    #
                    # Increment for the next iteration
                    #
                    offset += downloadedDataCount
                    log.debug(f'        downloadedDataCount: {downloadedDataCount}')
                    if (saveCtipDataFiles):
                        log.debug(f'             savedDataCount: {savedDataCount}')
                    log.debug(f'   totalDownloadedDataCount: {totalDownloadedDataCount}')

                    # Check for overall data download completion
                    if (offset > totalRowCount):
                        # Download completed
                        log.debug(f"{BASE_SPACE} ----->> offset: {offset:07d} // totalRowCount: {totalRowCount:07d} ::> API download completed.  Exit processing. <<-----")
                        break                    
                else:
                    # Processing has completed
                    log.critical(f'{BASE_SPACE} Completed CTIP {ctipApi} API processing')
                    break
            # Check for 403 response
            elif apiResponse.status_code == HTTPStatus.FORBIDDEN.value:
                log.error('Encountered 403 error. Confirm that your IP address is on the CTIP API AllowList.')
                SaveErrorResponseHtml(htmlData=apiResponse.text, eventName='403error')
                break # Cannot continue -- Exit out of the loop
            else:
                # CTIP API error
                log.error(f'{BASE_SPACE} CtipApi Response Status Code: {apiResponse.status_code}')
                log.error(f'{BASE_SPACE} CtipApi Response Text:        {apiResponse.text}')
                log.error(f'{BASE_SPACE} CtipApi Response Content:     {apiResponse.content}')
                SaveErrorResponseHtml(htmlData=apiResponse.text, eventName=f'{apiResponse.status_code}error')
                break # Cannot continue -- Exit out of the loop
        
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
        # Report total files created/downloaded from the API
        log.critical(f'{BASE_SPACE} Total CTIP {ctipApi} files downloaded: {gzFileCount}')
        # Return total downloaded row count to CtipApi() caller
        return totalDownloadedDataCount

def WriteDataToFile(destFile: str, data: bytes):
    """
    Create file and save content to the file

    Args:
        destFile (str): the file to create
        data (bytes): the data to save to the file
    """

    with open(destFile, 'wb') as file:
        file.write(data)

def GetSavedDataCount(sourceFile: str) -> int:
    """
    Determine number of data rows saved to file

    Args:
        sourceFile (str): the file path containing the GZip compressed data saved from the API 

    Returns:
        int: the number of CTIP data items saved to the file
    """

    processedDataRows = 0
    with gzip.open(sourceFile, 'rt', encoding='utf-8') as gzFile:
        ctipData = json.load(gzFile)
        processedDataRows = len(ctipData)
    return processedDataRows

def GetDownloadedDataCount(data: bytes) -> int:
    """
    Determine number of data rows downloaded from the API

    Args:
        data (bytes): the GZip compressed data downloaded from the API 

    Returns:
        int: the number of CTIP data items downloaded from the API
    """

    processedDataRows = 0
    with gzip.GzipFile(fileobj=BytesIO(data)) as gzFile:
        jsonBytes = gzFile.read()
    ctipData = json.loads(jsonBytes.decode('utf-8'))
    processedDataRows = len(ctipData)
    log.debug(f'{BASE_SPACE} Downloaded Count: {processedDataRows}')
    return processedDataRows

def UncompressAndProcessCtipData(data: bytes, ctipDataset: str) -> int:
    """
    Uncompress CTIP data from the API, and process as desired

    Args:
        data (bytes): the GZip compressed data downloaded from the API 
        ctipDataset (str): the CTIP dataset contained in data - CTIP_API_FRAUD_TSF

    Returns:
        int: the number of CTIP data objects 
    """

    downloadedCtipItems = 0
    with gzip.GzipFile(fileobj=BytesIO(data)) as gzFile:
        jsonBytes = gzFile.read()
    # Decoded the downloaded CTIP data into a list of CTIP data JSON objects to be used for further processing        
    ctipData = json.loads(jsonBytes.decode('utf-8'))
    downloadedCtipItems = len(ctipData)
    log.debug(f'{BASE_SPACE} Downloaded CTIP Data Item Count: {downloadedCtipItems}')

    if (ctipDataset==CTIP_API_FRAUD_TSF):
        log.info(f'{BASE_SPACE} Processing uncompressed CTIP TSF Data')
        
        itemCount = 0
        for objCtipData in ctipData:        
            # Process the line of CTIP JSON data
            itemCount += 1

            # Display a realtime progress counter to console only
            SetStatusMessage(f'Processing CTIP Tech Support Fraud data object: {itemCount} / {downloadedCtipItems}')

            # *******************************************************************************************
            # *******************************************************************************************
            # *******************************************************************************************
            # 
            # TODO: Add custom processing here to ingest CTIP TSF data (objCtipData) into your environment (database, SIEM)
            log.info(f'{json.dumps(objCtipData)}')
            #
            # *******************************************************************************************
            # *******************************************************************************************
            # *******************************************************************************************


    return downloadedCtipItems

def SaveErrorResponseHtml(htmlData: str, eventName: str):
    """
    Save the HTML from a error response to a local file for analysis

    Args:
        htmlData (str): the HTML content returned in the error message from the API 
        eventName (str): a custom event name used to have the saved HTML file 
    """

    # Confirm a local destination directory exists, create it if necessary
    if not os.path.exists(HTML_FILES_DIRECTORY):
        log.info(f'\tCreating HtmlFiles Directory: {HTML_FILES_DIRECTORY}')
        os.makedirs(HTML_FILES_DIRECTORY)

    destinationFilename = os.path.join(HTML_FILES_DIRECTORY, f'{eventName}_{datetime.now(timezone.utc).strftime("%Y.%m.%d_%H.%M.%S")}z.html')
    log.critical(f'\tSaving error HTML to: {destinationFilename}')
    with open(destinationFilename, 'w') as file:
        file.write(htmlData)

def SetStatusMessage(message: str):
    """
    Sets/updates a status message displayed on the console/terminal to the provided message

    Args:
        message (str): the message to display 
    """

    print(f'{message}', end="\r", flush=True)
    
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
    Builds the commandline that was used to launch dcuctiptsfapi.py

    Returns:
        string: a string representing the commandline used to launch dcuctiptsfapi.py
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
    log.critical('                             Version  1.1                              ')
    log.critical('')
    log.critical('01000100 01000011 01010101 00100000 01000011 01010100 01001001 01010000')
    log.critical('01000100 01000011 01010101 00100000 01000011 01010100 01001001 01010000')
    log.critical('#######################################################################')
    log.critical('#######################################################################')
    log.critical('')
    log.critical(f'Build {BUILD_VERSION}')
    log.critical('')

    # Configure and Process command line arguments
    parser = argparse.ArgumentParser(description='dcuctiptsfapi - DCU CTIP API Download Utility\
	\n\nConnects to the CTIP API to download and processes DCU CTIP data for the CTIP TSF dataset.'
		, prog='dcuctiptsfapi.py'
		, formatter_class=RawTextHelpFormatter)

    parser.add_argument('subscription_key', help=f'The CTIP API access key issued by DCU')
    parser.add_argument('--subscription_name', '-sn', default='dcuctiptsfapi', help='Used to name the downloaded data file(s)\nDefault setting is "dcuctiptsfapi"')
    parser.add_argument('--daysago', '-da', type=int, default=180, help='The timespan in days to query historical CTIP API data\nRange of acceptable values is 1..180\nDefault setting is 180 (all data)')
    parser.add_argument('--savectipdata',  '-save', action='store_true', help='Flag to save downloaded CTIP data to local files \nSave to files is disabled by default')
    parser.add_argument('--verbose',  '-v', action='store_true', help='Flag to display verbose output \nVerbose output is disabled by default')
    parser.add_argument('--debug',  '-d', action='store_true', help='Flag to display debug output \nDebug output is disabled by default')
    args = parser.parse_args()

    # Set the Subscription Key API token 
    apiToken = args.subscription_key

    # Set the subscription name value 
    subscriptionName = args.subscription_name

    # Set the daysago value 
    daysAgo = args.daysago

    # Set the savectipdata flag
    saveCtipDataFiles = False
    if args.savectipdata:
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

        # Display program configuration data
        log.critical('')
        log.info(f'Command line:         {GetCommandLine()}')
        # log.debug(f'Subscription Key:  {apiToken}')
        log.critical(f'Subscription Name:    {subscriptionName}')
        log.critical(f'Timespan (days):      {daysAgo}')
        log.critical(f'Artifacts:            {BASE_DIRECTORY}')
        log.critical(f'Save CTIP Data Files: {saveCtipDataFiles}')
        log.critical('') 
        log.critical('')
        log.critical(f'dcuctiptsfapi started processing at {FormatDateTimeYMDHMS(startTimestampLocal)}L / {FormatDateTimeYMDHMS(startTimestampUtc)}Z')
        log.critical('')

        # Create counters
        totalTsfDataItems = 0
 
        #
        # Call the CTIP TSF API
        #
        log.critical('')
        log.critical(f'Download CTIP TSF dataset...')
        (totalTsfDataItems) = CtipFraudApi(ctipApi=CTIP_API_FRAUD_TSF, 
                                           subscriptionName=subscriptionName, 
                                           subscriptionKey=apiToken, 
                                           daysAgo=daysAgo,
                                           saveCtipDataFiles=saveCtipDataFiles)

        log.critical('')
        log.critical(f'Total CTIP TSF Dataset Items: {(totalTsfDataItems)}')
        log.critical('')
    except KeyboardInterrupt:
        log.error('')
        log.error('#############################################')
        log.error('dcuctiptsfapi.py aborted by user.')
        log.error('#############################################')
        sys.exit(0)
    except Exception as error:
        log.error('#############################################')
        log.error('General Error during dcuctiptsfapi.py processing.')
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
        log.critical(f'dcuctiptsfapi started processing at:   {FormatDateTimeYMDHMS(startTimestampLocal)}L / {FormatDateTimeYMDHMS(startTimestampUtc)}Z')
        log.critical(f'dcuctiptsfapi completed processing at: {FormatDateTimeYMDHMS(endTimestampLocal)}L / {FormatDateTimeYMDHMS(endTimestampUtc)}Z')
        log.critical('')
        log.critical(f'dcuctiptsfapi total processing time:   {executionTime} ')
        log.critical('')
        if saveCtipDataFiles:
            log.critical(f'CTIP data files: {CTIP_DATA_DIRECTORY}')
            log.critical('')
        log.critical(f'Log file: {os.path.join(os.getcwd(), LOG_FILENAME)}')
        log.critical('')
        log.critical('######################################################')
        log.critical('dcuctiptsfapi completed.   ')
        log.critical('######################################################')

if __name__ == '__main__':
    main()