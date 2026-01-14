# DCU Cyber Threat Intelligence Program

## CTIP API Python Toolkit 

Microsoft DCU shares CTIP datasets through the CTIP API to enable automated, scalable access to threat intelligence. The DCU's **CTIP API Python Toolkit** is provided to accelerate integration by offering ready‑to‑use utilities and reference implementations.

These Python samples demonstrate end‑to‑end workflows, including API authentication, data retrieval, pagination handling, and downstream data processing.

For full endpoint definitions, parameters, and response schemas, refer to the **CTIP API Technical Reference** in the *CTIP Encyclopedia*.

## dcuctipapi - DCU CTIP API Utility

**dcuctipapi** is a utility for connecting to the DCU CTIP API to download and process CTIP datasets.

> **dcuctipapi.py**
>
>> dcuctipapi.py (`/dcuctipapi/dcuctipapi.py`) is the Python implementation.  See requirements.txt (`/dcuctipapi/requirements.txt`) for required libraries. <br><br>

```
usage: dcuctipapi.py [-h] --subscription-key SUBSCRIPTION_KEY [--subscription-name SUBSCRIPTION_NAME] [--hours-ago HOURS_AGO] [--save-ctip-data] [--verbose] [--debug]

dcuctipapi - DCU CTIP API Download Utility

Connects to the CTIP API to download and processes DCU CTIP data for the CTIP Infected and CTIP C2 datasets.

options:
  -h, --help            show this help message and exit
  --subscription-key, -key SUBSCRIPTION_KEY
                        The CTIP API access key issued by DCU [required]
  --subscription-name, -sn SUBSCRIPTION_NAME
                        Used to name the downloaded data file(s)
                        Default setting is "dcuctipapi"
  --hours-ago, -ha HOURS_AGO
                        The timespan in hours to query historical CTIP API data
                        Range of acceptable values is 1..72
                        Default setting is 1 hour
  --save-ctip-data, -save
                        Flag to save downloaded CTIP data to local files
                        Save to files is disabled by default
  --verbose, -v         Flag to display verbose output
                        Verbose output is disabled by default
  --debug, -d           Flag to display debug output
                        Debug output is disabled by default
```


## dcuctipapi2stix - DCU CTIP API to STIX Utility

**dcuctipapi2stix** is a utility for connecting to the DCU CTIP API to download CTIP datasets and convert the CTIP data objects to STIX bundles.

> **dcuctipapi.py**
>
>> dcuctipapi2stix.py (`/dcuctipapi2stix/dcuctipapi2stix.py`) is the Python implementation.  See requirements.txt (`/dcuctipapi2stix/requirements.txt`) for required libraries. <br><br>

```
usage: dcuctipapi2stix.py [-h] --subscription-key SUBSCRIPTION_KEY [--subscription-name SUBSCRIPTION_NAME] [--hours-ago HOURS_AGO] [--save-ctip-data] [--save-stix-data] [--verbose] [--debug]

dcuctipapi2stix - DCU CTIP API Download Utility

Connects to the CTIP API to download and processes DCU CTIP data for the CTIP Infected and CTIP C2 datasets.

options:
  -h, --help            show this help message and exit
  --subscription-key, -key SUBSCRIPTION_KEY
                        The CTIP API access key issued by DCU [required]
  --subscription-name, -sn SUBSCRIPTION_NAME
                        Used to name the downloaded data file(s)
                        Default setting is "dcuctipapi2stix"
  --hours-ago, -ha HOURS_AGO
                        The timespan in hours to query historical CTIP API data
                        Range of acceptable values is 1..72
                        Default setting is 1 hour
  --save-ctip-data, -sc
                        Flag to save downloaded CTIP data to local files
                        Save to files is disabled by default
  --save-stix-data, -ss
                        Flag to save generated STIX data to local files
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
usage: dcuctiptsfapi.py [-h] --subscription-key SUBSCRIPTION_KEY [--subscription-name SUBSCRIPTION_NAME] [--days-ago DAYS_AGO] [--save-ctip-data] [--verbose] [--debug]

dcuctiptsfapi - DCU CTIP API Download Utility

Connects to the CTIP API to download and processes DCU CTIP data for the CTIP TSF dataset.

options:
  -h, --help            show this help message and exit
  --subscription-key, -key SUBSCRIPTION_KEY
                        The CTIP API access key issued by DCU [required]
  --subscription-name, -sn SUBSCRIPTION_NAME
                        Used to name the downloaded data file(s)
                        Default setting is "dcuctiptsfapi"
  --days-ago, -da DAYS_AGO
                        The timespan in days to query historical CTIP API data
                        Range of acceptable values is 1..180
                        Default setting is 14
  --save-ctip-data, -save
                        Flag to save downloaded CTIP data to local files
                        Save to files is disabled by default
  --verbose, -v         Flag to display verbose output
                        Verbose output is disabled by default
  --debug, -d           Flag to display debug output
                        Debug output is disabled by default
```
