# DCU Cyber Threat Intelligence Program

## dcuctipapi - DCU CTIP API Utility

**dcuctipapi** is a utility for connecting to the DCU CTIP API to download and process CTIP datasets.

> **dcuctipapi.py**
>
>> dcuctipapi.py (`/dcuctipapi/dcuctipapi.py`) is the Python implementation.  See requirements.txt (`/dcuctipapi/requirements.txt`) for required libraries. <br><br>

```
usage: dcuctipapi.py [-h] [--subscription_name SUBSCRIPTION_NAME] [--hoursago HOURSAGO] [--savectipdata] [--verbose] [--debug] subscription_key

dcuctipapi - DCU CTIP API Download Utility

Connects to the CTIP API to download and processes DCU CTIP data for the CTIP Infected and CTIP C2 datasets.

positional arguments:
  subscription_key      The CTIP API access key issued by DCU

options:
  -h, --help            show this help message and exit
  --subscription_name, -sn SUBSCRIPTION_NAME
                        Used to name the downloaded data file(s)
                        Default setting is "dcuctipapi"
  --hoursago, -ha HOURSAGO
                        The timespan in hours to query historical CTIP API data
                        Range of acceptable values is 1..72
                        Default setting is 1 hour
  --savectipdata, -save
                        Flag to save downloaded CTIP data to local files
                        Save to files is disabled by default
  --verbose, -v         Flag to display verbose output
                        Verbose output is disabled by default
  --debug, -d           Flag to display debug output
                        Debug output is disabled by default
```


## dcuctipapi2stix - DCU CTIP API to STIX Utility

**dcuctipapi2stix** is a utility for connecting to the DCU CTIP API to download CTIP datasets and convert the CTIP data to STIX bundles.

> **dcuctipapi.py**
>
>> dcuctipapi2stix.py (`/dcuctipapi2stix/dcuctipapi2stix.py`) is the Python implementation.  See requirements.txt (`/dcuctipapi2stix/requirements.txt`) for required libraries. <br><br>

```
usage: dcuctipapi2stix.py [-h] [--subscription_name SUBSCRIPTION_NAME] [--hoursago HOURSAGO] [--savectipdata] [--savestixdata] [--verbose] [--debug] subscription_key

dcuctipapi2stix - DCU CTIP API Download and STIX Translation Utility

Connects to the CTIP API to download DCU CTIP data for the CTIP Infected and CTIP C2 datasets, and convert the CTIP data to STIX bundles.

positional arguments:
  subscription_key      The CTIP API access key issued by DCU

options:
  -h, --help            show this help message and exit
  --subscription_name, -sn SUBSCRIPTION_NAME
                        Used to name the downloaded data file(s)
                        Default setting is "dcuctipapi"
  --hoursago, -ha HOURSAGO
                        The timespan in hours to query historical CTIP API data
                        Range of acceptable values is 1..72
                        Default setting is 1 hour
  --savectipdata, -sc   Flag to save downloaded CTIP data to local files
                        Save to files is disabled by default
  --savestixdata, -ss   Flag to save generated STIX data to local files
                        Save to files is disabled by default
  --verbose, -v         Flag to display verbose output
                        Verbose output is disabled by default
  --debug, -d           Flag to display debug output
                        Debug output is disabled by default
```


## dcuctiptsfapi - DCU CTIP TSF API Utility

**dcuctiptsfapi** is a utility for connecting to the DCU CTIP API to download and process the CTIP TSF dataset.

> **dcuctiptsfapi.py**
>
>> dcuctiptsfapi.py (`/dcuctiptsfapi/dcuctiptsfapi.py`) is the Python implementation.  See requirements.txt (`/dcuctiptsfapi/requirements.txt`) for required libraries. <br><br>

```
usage: dcuctiptsfapi.py [-h] [--subscription_name SUBSCRIPTION_NAME] [--daysago DAYSAGO] [--savectipdata] [--verbose] [--debug] subscription_key

dcuctiptsfapi - DCU CTIP API Download Utility

Connects to the CTIP API to download and processes DCU CTIP data for the CTIP TSF dataset.

positional arguments:
  subscription_key      The CTIP API access key issued by DCU

options:
  -h, --help            show this help message and exit
  --subscription_name, -sn SUBSCRIPTION_NAME
                        Used to name the downloaded data file(s)
                        Default setting is "dcuctiptsfapi"
  --daysago, -da DAYSAGO
                        The timespan in days to query historical CTIP API data
                        Range of acceptable values is 1..180
                        Default setting is 180 (all data)
  --savectipdata, -save
                        Flag to save downloaded CTIP data to local files
                        Save to files is disabled by default
  --verbose, -v         Flag to display verbose output
                        Verbose output is disabled by default
  --debug, -d           Flag to display debug output
                        Debug output is disabled by default
```
