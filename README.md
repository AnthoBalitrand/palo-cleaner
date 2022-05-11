# Palo Alto objects cleaner 

Exhausted by the mess your Panorama has become, because of Address objects existing in 2, 3, or more copies ? 
Because of Service objects being duplicates on your device-groups, while also existing as shared ? 

This tool is for you. 

It will help you cleaning your device-groups hierarchy, by removing all duplicates and replacing them by the best
(and highest) object in the hierarchy. 

## Installation 

#### 1. Clone the repo to your working directory 
```
$ git clone https://github.com/AnthoBalitrand/palo-cleaner.git
```

#### 2. Create a virtual environment (optional) and activate it 
```
$ python3 -m venv ./venv
$ source venv/bin/activate
```

#### 3. Install the requirements 
```
$ pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

## Usage 

You can display the script startup arguments information by using the --help argument : 

```
$ python3 main.py --help
usage: main.py [-h] --panorama-url PANORAMA_URL [--device-groups DEVICE_GROUPS [DEVICE_GROUPS ...]] --api-user API_USER [--api-password API_PASSWORD] [--apply-cleaning]
               [--delete-upward-objects] [--verbosity] [--max-days-since-change MAX_DAYS_SINCE_CHANGE] [--max-days-since-hit MAX_DAYS_SINCE_HIT]
               [--tiebreak-tag TIEBREAK_TAG] [--apply-tiebreak-tag] [--no-report] [--split-report]

optional arguments:
  -h, --help            show this help message and exit
  --panorama-url PANORAMA_URL
                        Address of the Panorama server to which to connect
  --device-groups DEVICE_GROUPS [DEVICE_GROUPS ...]
                        List of device-groups to be included in the cleaning process
  --api-user API_USER   Username to use for API connection to Panorama
  --api-password API_PASSWORD
                        Password to use for API connection to Panorama
  --apply-cleaning      Apply cleaning operation
  --delete-upward-objects
                        Deletes upward unused objects (shared + intermediates) if all childs are analyzed
  --verbosity, -v       Verbosity level (from 1 to 3)
  --max-days-since-change MAX_DAYS_SINCE_CHANGE
                        Don't apply any change to rules not having be modified since more than X days
  --max-days-since-hit MAX_DAYS_SINCE_HIT
                        Don't apply any change to rules not being hit since more than X days
  --tiebreak-tag TIEBREAK_TAG
                        Tag used to choose preferred replacement object in case of multiple ones (overrides default choice)
  --apply-tiebreak-tag  Applies the tag defined on the --tiebreak-tag argument to objects choosen by the choice algorithm
  --no-report           Does not generates job reports
  --split-report        Split the report file (1 per device-group)

```

Here's a more detailed description of those different parameters : 

| Parameter | values | Description |
| --------- | ------ | ----------- |
| -h or --help | N/A | **(Mandatory)** Displays the list of parameters and a quick description |
| --panorama-url | IP or FQDN | **(Mandatory)** The IP or FQDN of the Panorama appliance to which to connect. If using the --apply-cleaning keyword, make sure this is the active appliance in an high-availability deployment |
| --device-groups | list of strings | The list (with space as a delimiter) of device-groups ta nalyze, in case you want to limit the analyzis / cleaning perimeter | 
| --api-user | string | **(Mandatory)** The XML API user to use for connection to Panorama, and to the firewall appliances if you use the --max-days-since-hit argument | 
| --api-password | string | The password associated to the --api-user account. If you don't specify it as an argument, you will be prompted when starting the script | 
| --apply-cleaning | N/A | Use this argument if you don't want only a report, but if you want the script to change the policies / objects to remove the duplicates, on the perimeter defined by the --device-groups argument values | 
| -v or --verbosity | N/A | Add this argument several times (from 1 to 3) to increase the output log verbosity level | 
| --max-days-since-change | Integer | The number of days since when, if a rule has not been modified, it will not be included in the cleaning process. Needs to be used in conjunction with --max-days-since-hit | 
| --max-days-since-hit | Integer | The number of days since when, if a rule has not been hit, it will not be included in the cleaning process. Needs to be used in conjunction with --max-days-since-change | 
| --tiebreak-tag | string | To force usage of specific objects (which would normally not be chosen by the algorithm) if the provided tag has been applied to those objects | 
| --apply-tiebreak-tag | | Applies the taf defined on the --tiebreak-tag parameter to the choosen objects by the algorithm, to make sure they will remain choose at next script usages | 
| --no-report | | When used, does not create any html report for the run | 
| --split-report | | Will create multiple reports files (globally, one per device-group). Highly recommended in large environments if you don't want huge unexploitables html reports | 

## Capabilities 

This section will give you an overview of what this script is able to do, and what this script is **not** able to do. 

This is subject to evolution. 

Feel free to open new issues if something needs to be fixed / improved. 

- [x] Manage a multi-level hierarchy
- [x] Detect / replace duplicate objects on any device-group in the hierarchy
- [ ] Create objects as shared if there are duplicates "below" and an equivalent does not exists at this level 
- [ ] For AddressObjects having FQDN **name**, check if this value is accurate using a reverse DNS query 
- [x] Replace objects in static groups by duplicates existing at higher level in the hierarchy 
- [ ] Delete / replace duplicates groups
- [x] Replace objects in dynamic groups
- [x] Protect rules (and directly referenced objects) from modification, based on last change date / last hit date 
- [x] Run in dry-run mode, only to generate a report 

#### Objects-type supported 

The following objects types are analyzed and cleaned 

- [x] AddressObject (host, subnet, or FQDN)
- [x] Static AddressGroup
- [x] Tag
- [x] Service
- [x] ServiceGroup 

#### Rulebase types supported

The following rulebases are analyzed to find objects usage 

- [x] Security
- [x] NAT
- [x] Authentication

## Run logic 

This section will try to give you a clear understanding of the inner logic used in the analyze and cleaning process. 


#### 1 - Download device-groups hierarchy from Panorama

- Connection to Panorama
- Download and analysis of the device-groups hierarchy
- Compare with the list of device-groups provided in the --device-groups argument to know which ones need to be analyzed / cleaned 
- Display of the hierarchy and analyzed / cleaned device-groups to the user

    **Remarks :**
- If no device-group is specific at startup, all device-groups are considered included 
- If all child device-groups of a given parent are included, the parent is implicitly included in the process 

Example : 

No device-groups specified, all hierarchy levels are included in the analyzis / cleaning process :
```
$ python3 main.py --panorama-url 192.168.192.10 --api-user apiuser
[22:56:28] [ Panorama ] Connection established                                                                                                            PaloCleaner.py:112
Discovered hierarchy tree is the following :
(  + are directly included  /  * are indirectly included  /  - are not included  )
 F (Fully included = cleaned) / P (Partially included = not cleaned) 
╭────────────────────────────────────────────────────────────────────────────────────────────╮
│ + F shared                                                                                 │
│ ├── + F mickey                                                                             │
│ ├── + F winnie                                                                             │
│ └── + F bambi                                                                              │
│     ├── + F geno                                                                           │
│     └── + F gurri                                                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────╯
```

Specifying 'mickey' and 'winnie' at startup :

```
$ python3 main.py --panorama-url 192.168.192.10 --api-user apiuser --device-groups mickey winnie
[22:56:40] [ Panorama ] Connection established                                                                                                            PaloCleaner.py:112
Discovered hierarchy tree is the following :
(  + are directly included  /  * are indirectly included  /  - are not included  )
 F (Fully included = cleaned) / P (Partially included = not cleaned) 
╭────────────────────────────────────────────────────────────────────────────────────────────╮
│ * P shared                                                                                 │
│ ├── + F mickey                                                                             │
│ ├── + F winnie                                                                             │
│ └── - bambi                                                                                │
│     ├── - geno                                                                             │
│     └── - gurri                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────╯
```
Note that the 'shared' level is included in the process (it will be analyzed as it is above some analyzed device-groups), 
but it is marked as "P" = Partially included, meaning that it will not be cleaned. 


Specifying 'geno' and 'gurri' at startup : 

```
$ python3 main.py --panorama-url 192.168.192.10 --api-user apiuser --device-groups mickey winnie
[22:56:50] [ Panorama ] Connection established                                                                                                            PaloCleaner.py:112
Discovered hierarchy tree is the following :
(  + are directly included  /  * are indirectly included  /  - are not included  )
 F (Fully included = cleaned) / P (Partially included = not cleaned) 
╭────────────────────────────────────────────────────────────────────────────────────────────╮
│ * P shared                                                                                 │
│ ├── - mickey                                                                               │
│ ├── - winnie                                                                               │
│ └── * F bambi                                                                              │
│     ├── + F geno                                                                           │
│     └── + F gurri                                                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────╯
```

As all the childs of the device-group "bambi" are explicitly included in the --device-groups argument, 
"bambi" is implicitly included too. 
"Mickey" and "winnie" will not be analyzed (neither cleaned). 
The "shared" level will be analyzed, but not cleaned. 