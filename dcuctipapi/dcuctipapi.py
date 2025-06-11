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
from io import BytesIO
from http import HTTPStatus
import requests  # requires installation: pip install requests

# Program Version 
BUILD_VERSION = '2025.06.10'

# CTIP API settings
CTIP_API_BASE_URL                = 'https://api.dcuctip.com/ctip'
CTIP_API_INFECTED                = 'infected'
CTIP_API_C2                      = 'c2'
CTIP_API_OFFSET_INIT             = 1
CTIP_API_MAX_RETRIES             = 3
CTIP_API_MAX_RETRY_DELAY_SECONDS = 10
CTIP_API_RETRY_DELAY_MULTIPLIER  = 3
CTIP_USER_AGENT                  = 'Microsoft.DCU.CTIP.DcuCtipApi'

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

def CtipApi(ctipApi: str, subscriptionName: str, subscriptionKey: str, hoursAgo: int, only_return_data: bool = False):
    """
    Connect to the CTIP API (Infected or C2) to download data for the desired timeframe (hoursAgo)

    Args:
        ctipApi (str): the target CTIP API endpoint - use constants CTIP_API_INFECTED or CTIP_API_C2
        subscriptionName (str): a descriptive string used to name output files
        subscriptionKey (str): the subscription key provided by DCU to grant CTIP API access
        hoursAgo (int): the timeframe to retrieve data from the CTIP API; valid values are 1..72
        only_return_data (bool): if True, returns all data as a list and does not save files

    Returns:
        int or list: the total number of CTIP data items downloaded from the API, or the list of items if only_return_data is True
    """

    all_data = []  # Para acumular todos los datos si only_return_data está activo

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

        log.critical(f'>>>> Connecting to CTIP API: {ctipApi.title()}')
        log.info(f'          Subscription Name: {subscriptionName}')
        log.info(f'           Subscription Key: {subscriptionKey}')
        log.info(f'           Timespan (hours): {hoursAgo}')
        log.critical(f'     [sc: Saved Data Count  //  tc: Total Downloaded Count]')

        #
        # Connect to CTIP API and download data in chunks
        #
        while True:
            # Setup request URL
            apiUrl = f"{CTIP_API_BASE_URL}/{ctipApi}?hoursago={hoursAgo}&offset={offset}"
            log.info(f'                    API URL: {apiUrl}')
            log.debug(f'                 Processing: {offset:07d}/{totalRowCount}')

            # Send the API request
            log.debug(f'   Sending CTIP API Request: {apiUrl}')
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
                    log.critical(f"{BASE_SPACE} Downloading [~{totalRowCount:07d}] rows of data from the CTIP {ctipApi.title()} API")

                # Determine number of data rows from the downloaded content
                log.info(f'{BASE_SPACE} Determine the number of data rows downloaded')
                # Aquí descomprimimos y parseamos el JSON para devolverlo si only_return_data
                with gzip.GzipFile(fileobj=BytesIO(apiResponse.content)) as gzFile:
                    jsonBytes = gzFile.read()
                ctipData = json.loads(jsonBytes.decode('utf-8'))
                downloadedDataCount = len(ctipData)
                totalDownloadedDataCount += downloadedDataCount # Add downloaded count to total downloaded counter

                # Check for data to process
                if (downloadedDataCount > 0):
                    #
                    # Save Downloaded CTIP data to a local file
                    #
                    log.info(f"{BASE_SPACE} Downloaded [dc:{downloadedDataCount:07d} // tc:{totalDownloadedDataCount:07d}] rows of CTIP {ctipApi.title()} data")

                    if not only_return_data:
                        # Save the GZip compressed json payload to a local file
                        gzFileCount += 1
                        gzFilename = os.path.join(CTIP_DATA_DIRECTORY, f'{subscriptionName}_CTIP_{ctipApi.title()}_{ctipDataFileDateTime}_{gzFileCount:03d}.json.gz')
                        log.info(f"{BASE_SPACE} Target destination file: {gzFilename}")
                        WriteDataToFile(gzFilename, apiResponse.content)

                        # Determine number of data rows saved
                        log.info(f'{BASE_SPACE} Determine the number of data rows saved to file')
                        savedDataCount = GetSavedDataCount(gzFilename)
                        # sc = saved count for this iteration
                        # tc = total saved count for this API session
                        log.critical(f"{BASE_SPACE} Saved [sc:{savedDataCount:07d} // tc:{totalDownloadedDataCount:07d}] rows of CTIP {ctipApi.title()} data to: {os.path.basename(gzFilename)}")

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
                        offset += savedDataCount
                        log.debug(f'        downloadedDataCount: {downloadedDataCount}')
                        log.debug(f'             savedDataCount: {savedDataCount}')
                        log.debug(f'   totalDownloadedDataCount: {totalDownloadedDataCount}')

                        # Check for overall data download completion
                        if (offset > totalRowCount):
                            # Download completed
                            log.debug(f"{BASE_SPACE} ----->> offset: {offset:07d} // totalRowCount: {totalRowCount:07d} ::> API download completed.  Exit processing. <<-----")
                            break                    
                    else:
                        # Si only_return_data, solo acumulamos los datos y avanzamos el offset
                        all_data.extend(ctipData)
                        offset += downloadedDataCount
                        if (offset > totalRowCount):
                            break
                else:
                    # Processing has completed
                    log.critical(f'{BASE_SPACE} Completed CTIP {ctipApi.title()} API processing')
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
        log.critical(f'{BASE_SPACE} Total CTIP {ctipApi.title()} files downloaded: {gzFileCount}')
        # Return all_data si only_return_data, si no el conteo clásico
        if only_return_data:
            return all_data
        else:
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
        ctipDataset (str): the CTIP dataset contained in data - CTIP_API_INFECTED or CTIP_API_C2 

    Returns:
        int: the number of CTIP data objects 
    """

    downloadedCtipItems = 0
    with gzip.GzipFile(fileobj=BytesIO(data)) as gzFile:
        jsonBytes = gzFile.read()
    ctipData = json.loads(jsonBytes.decode('utf-8')) # This is a decoded list of CTIP data JSON objects
    downloadedCtipItems = len(ctipData)
    log.debug(f'{BASE_SPACE} Downloaded CTIP Data Item Count: {downloadedCtipItems}')

    if (ctipDataset==CTIP_API_INFECTED):
        log.info(f'{BASE_SPACE} Processing uncompressed CTIP Infected Data')
        # *******************************************************************************************
        # *******************************************************************************************
        # *******************************************************************************************
        # 
        # TODO: Add custom processing here to ingest CTIP Infected data (ctipData) into your environment (database, SIEM)
        #
        # *******************************************************************************************
        # *******************************************************************************************
        # *******************************************************************************************

    elif (ctipDataset==CTIP_API_C2):
        log.info(f'{BASE_SPACE} Processing uncompressed CTIP C2 Data')
        # *******************************************************************************************
        # *******************************************************************************************
        # *******************************************************************************************
        # 
        # TODO: Add custom processing here to ingest CTIP C2 data (ctipData) into your environment (database, SIEM)
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
    log.critical('                             Version  1.0                              ')
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

    parser.add_argument('subscription_key', help=f'The CTIP API access key issued by DCU')
    parser.add_argument('--subscription_name', '-sn', default='dcuctipapi', help='Used to name the downloaded data file(s)\nDefault setting is "dcuctipapi"')
    parser.add_argument('--hoursago', '-ha', type=int, default=1, help='The timespan in hours to query historical CTIP API data\nRange of acceptable values is 1..72\nDefault setting is 1 hour')
    parser.add_argument('--verbose',  '-v', action='store_true', help='Flag to display verbose output \nVerbose output is disabled by default')
    parser.add_argument('--debug',  '-d', action='store_true', help='Flag to display debug output \nDebug output is disabled by default')
    parser.add_argument('--only-return-data', action='store_true', help='Solo devuelve los datos descargados en vez de grabar archivos')
    args = parser.parse_args()

    # Set the Subscription Key API token 
    apiToken = args.subscription_key

    # Set the subscription name value 
    subscriptionName = args.subscription_name

    # Set the hoursago value 
    hoursAgo = args.hoursago

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
        if not os.path.exists(CTIP_DATA_DIRECTORY):
            log.debug(f'Creating CTIP Data Directory: {CTIP_DATA_DIRECTORY}')
            os.makedirs(CTIP_DATA_DIRECTORY)

        # Get the current UTC date/time
        startTimestampUtc = datetime.now(timezone.utc)
        startTimestampLocal = datetime.now()

        # Display program configuration data
        log.critical('')
        log.info(f'Command line:      {GetCommandLine()}')
        # log.debug(f'Subscription Key:  {apiToken}')
        log.critical(f'Subscription Name: {subscriptionName}')
        log.critical(f'Timespan (hours):  {hoursAgo}')
        log.critical(f'Artifacts:         {BASE_DIRECTORY}')
        log.critical('') 
        log.critical('')
        log.critical(f'dcuctipapi started processing at {FormatDateTimeYMDHMS(startTimestampLocal)}L / {FormatDateTimeYMDHMS(startTimestampUtc)}Z')
        log.critical('')

        # Validate hoursAgo setting
        if hoursAgo not in range(1, 73):
            raise ValueError(f'hoursAgo value [{hoursAgo}] is out of the allowed range [1..72].')
        
        # Create counters
        totalInfectedDataItems = 0
        totalC2DataItems = 0
 
        #
        # Call the CTIP Infected API
        #
        log.critical('')
        log.critical(f'Download CTIP Infected dataset...')
        infected_result = CtipApi(
            ctipApi=CTIP_API_INFECTED, 
            subscriptionName=subscriptionName, 
            subscriptionKey=apiToken, 
            hoursAgo=hoursAgo,
            only_return_data=args.only_return_data
        )

        #
        # Call the CTIP C2 API
        #
        log.critical('')
        log.critical(f'Download CTIP C2 dataset...')
        c2_result = CtipApi(
            ctipApi=CTIP_API_C2, 
            subscriptionName=subscriptionName, 
            subscriptionKey=apiToken, 
            hoursAgo=hoursAgo,
            only_return_data=args.only_return_data
        )

        if args.only_return_data:
            print(json.dumps({
                "infected": infected_result,
                "c2": c2_result
            }, ensure_ascii=False, indent=2))
            log.critical(f'Total CTIP Infected Dataset Items: {len(infected_result)}')
            log.critical(f'Total CTIP C2 Dataset Items:       {len(c2_result)}')
        else:
            log.critical(f'Total CTIP Infected Dataset Items: {infected_result}')
            log.critical(f'Total CTIP C2 Dataset Items:       {c2_result}')
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
        log.critical(f'CTIP data files: {CTIP_DATA_DIRECTORY}')
        log.critical('')
        log.critical(f'Log file: {os.path.join(os.getcwd(), LOG_FILENAME)}')
        log.critical('')
        log.critical('######################################################')
        log.critical('dcuctipapi completed.   ')
        log.critical('######################################################')

if __name__ == '__main__':
    main()
