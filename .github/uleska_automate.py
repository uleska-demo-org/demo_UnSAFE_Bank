import requests
import json
import argparse
import time
import sys

#Capture command line arguments
arguments = sys.argv



#Capture command line arguments
arg_options = argparse.ArgumentParser(description="Runs owasp-dependency-check against the specified folder or /tmp/src")
arg_options.add_argument('--application', required=True, type=str)
arg_options.add_argument('--version', type=str)


args = arg_options.parse_args()

application = ""
version = ""


#Grab the BaseUrl from the command line arguments
if args.application is not None:
    application = args.application
    #print("Application: " + application)

#Grab the WebInspect API Username from the command line arguments
if args.version is not None:
    version = args.version
    #print("Version: " + version)
    
    
s = requests.Session()


s.headers.update({
    'Content-Type': "application/json",
    'cache-control': "no-cache",
    'Authorization': "Bearer c64Ca28whEAIkFYlzO8clRutrlwVws2pFRwEz09Pm9I"
    })



#Build API URL
host = "https://uleska-live-one.uleska.com/"



##### Kick off a scan
ScanURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version + "/scan"

#Check for running scans
try:
    StatusResponse = s.request("Get", ScanURL)
except requests.exceptions.RequestException as err:
    print ("Exception running scan\n" + str(err))
    sys.exit()
    
if StatusResponse.status_code != 200:
    #Something went wrong, maybe server not up, maybe auth wrong
    print("Non 200 status code returned when running scan.  Code [" + str(StatusResponse.status_code) + "]")
    sys.exit()
    

#### Scan should be running, run check scans to see if it's still running

scanfinished = False

CheckScanURL = host + "SecureDesigner/api/v1/scans"

while scanfinished is False:
    
    try:
        StatusResponse = s.request("Get", CheckScanURL)
    except requests.exceptions.RequestException as err:
        print ("Exception checking for running scan\n" + str(err))
        sys.exit()
        
    if StatusResponse.status_code != 200:
        #Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when checking for running scan.  Code [" + str(StatusResponse.status_code) + "]")
        sys.exit()
        
    #### we have a response, check to see if this scan is still running.  Note there could be multiple scans running
    running_scans_json = ""
    
    try:
        running_scans_json = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print ("Invalid JSON when checking for running scans.  Exception: [" + str(jex) + "]")
        sys.exit()
    
    if len(running_scans_json) == 0:
        #### if there's no scans running, then it must have finished
        print ("No more scans running\n")
        scanfinished = True
        break
    
    for scan in running_scans_json:
        if 'versionId' in scan:
            if scan['versionId'] == version:
                ### our scan is still running, sleep and return
                print ("Our Toolkit " + version + " is still running, waiting...\n")
                time.sleep(10)
                
            else:
                
                ### our scan isn't running
                 print ("Our Toolkit " + version + " has completed\n")
                 scanfinished = True
                 break
        else:
            print ("No versionId in the scan\n")


#### Scan is finished, now we need to get the latest report Id

GetVersionReportsURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version

try:
    StatusResponse = s.request("Get", GetVersionReportsURL)
except requests.exceptions.RequestException as err:
    print ("Exception getting version reports\n" + str(err))
    sys.exit()
    
if StatusResponse.status_code != 200:
    #Something went wrong, maybe server not up, maybe auth wrong
    print("Non 200 status code returned when getting version reports.  Code [" + str(StatusResponse.status_code) + "]")
    sys.exit()


version_info = ""

try:
    version_info = json.loads(StatusResponse.text)
except json.JSONDecodeError as jex:
    print ("Invalid JSON when checking for version reports.  Exception: [" + str(jex) + "]")
    sys.exit()
    

report_dict = []

class report_obj:
    id = ""
    vulncount = 0
    tools = ""


if 'reports' in version_info:
    for report in version_info['reports']:
        #print ("Report is as follows \n\n" + str(report))
        this_report = report_obj()
        
        if 'id' in report:
            this_report.id = report['id']
        
        if 'vulnerabilityCount' in report:
            this_report.vulncount = report['vulnerabilityCount']
        
        
        
        report_dict.append(this_report)
        

####### now we have the latest report, and the one previous to it (for now we're assuming there will be 2)
class issue_info:
    title = ""
    tool = ""
    total_cost = 0
    CVSS = ""
    

latest_report_handle = report_dict[-1]

GetLatestReportsURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version + "/reports/" + latest_report_handle.id + "/vulnerabilities"

print("\n" + GetLatestReportsURL + "\n")
      
try:
    StatusResponse = s.request("Get", GetLatestReportsURL)
except requests.exceptions.RequestException as err:
    print ("Exception getting latest reports\n" + str(err))
    sys.exit()
    
if StatusResponse.status_code != 200:
    #Something went wrong, maybe server not up, maybe auth wrong
    print("Non 200 status code returned when getting latest report.  Code [" + str(StatusResponse.status_code) + "]")
    sys.exit()


latest_report_info = ""

latest_report_issues = []
latest_report_titles = []

try:
    latest_report_info = json.loads(StatusResponse.text)
except json.JSONDecodeError as jex:
    print ("Invalid JSON when extracting latest report.  Exception: [" + str(jex) + "]")
    sys.exit()
        
        
for reported_issue in latest_report_info:
    
    this_issue = issue_info()
    
    if 'falsePositive' in reported_issue:
        if reported_issue['falsePositive'] is True:
            #print ("False positive being ignored\n")
            continue
    
    if 'title' in reported_issue:
        this_issue.title = reported_issue['title']
        latest_report_titles.append(reported_issue['title'])
    
    if 'tool' in reported_issue:
        this_issue.tool = reported_issue['tool']['title']
    
    if 'totalCost' in reported_issue:
        this_issue.total_cost = reported_issue['totalCost']
        
    if 'vulnerabilityDefinition' in reported_issue:
        this_issue.CVSS = reported_issue['vulnerabilityDefinition']['standards'][0]['description'] + " : " + reported_issue['vulnerabilityDefinition']['standards'][0]['title']
    
    latest_report_issues.append(this_issue)
        
total_risk = 0

for iss in latest_report_issues:
    #print ("Latest Reported Issue with title [" + iss.title + "] and tool [" + iss.tool + "] and cost [" + str(iss.total_cost) + "]" )
    total_risk = total_risk + iss.total_cost


print ("\nLatest security toolkit run:")
print ("    Total risk:                   = $" + str( f'{total_risk:,}' ))
print ("    Total issues:                 = " + str( len( latest_report_issues ) ) )





penultumate_report_handle = report_dict[-2]

GetPenultumateReportsURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version + "/reports/" + penultumate_report_handle.id + "/vulnerabilities"


#print (GetPenultumateReportsURL)

try:
    StatusResponse = s.request("Get", GetPenultumateReportsURL)
except requests.exceptions.RequestException as err:
    print ("Exception getting pen report\n" + str(err))
    sys.exit()
    
if StatusResponse.status_code != 200:
    #Something went wrong, maybe server not up, maybe auth wrong
    #print("Non 200 status code returned when getting penultumate report.  Code [" + str(StatusResponse.status_code) + "]")
    sys.exit()

penultumate_report_info = ""

penultumate_report_issues = []
penultumate_report_titles = []

try:
    penultumate_report_info = json.loads(StatusResponse.text)
except json.JSONDecodeError as jex:
    print ("Invalid JSON when extracting pen report.  Exception: [" + str(jex) + "]")
    sys.exit()
        
        
for pen_reported_issue in penultumate_report_info:
    
    this_issue = issue_info()
    
    if 'falsePositive' in pen_reported_issue:
        if pen_reported_issue['falsePositive'] is True:
            #print ("False positive being ignored\n")
            continue
    
    if 'title' in pen_reported_issue:
        this_issue.title = pen_reported_issue['title']
        penultumate_report_titles.append(pen_reported_issue['title'])
    
    if 'tool' in pen_reported_issue:
        this_issue.tool = pen_reported_issue['tool']['title']
    
    if 'totalCost' in pen_reported_issue:
        this_issue.total_cost = pen_reported_issue['totalCost']
    
    penultumate_report_issues.append(this_issue)
        
pen_total_risk = 0

for pen_iss in penultumate_report_issues:
    #print ("Penultumate Reported Issue with title [" + pen_iss.title + "] and tool [" + pen_iss.tool + "] and cost [" + str(pen_iss.total_cost) + "]" )
    pen_total_risk = pen_total_risk + pen_iss.total_cost


print ("\nPrevious security toolkit run:")
print ("    Total risk:                   = $" + str( f'{pen_total_risk:,}' ))
print ("    Total issues:                 = " + str( len( penultumate_report_issues ) ) )
        
if pen_total_risk == total_risk:
    print ("\nNo change in risk levels since last check\n")
elif pen_total_risk > total_risk:
    reduced = pen_total_risk - total_risk
    print ("\n    Risk level has REDUCED by       $" + str( f'{reduced:,}' ))
    reduced_percentage = ( 100 - ( 100 / pen_total_risk ) * total_risk )
    print ("    Risk level has REDUCED by       " + str( reduced_percentage )[0:4] + "%\n")
else:
    increased = total_risk - pen_total_risk
    print ("\n    Risk level has INCREASED by    $" + str( f'{increased:,}' ))
    increased_percentage = ( ( ( 100 / pen_total_risk  ) * total_risk ) - 100)
    print ("    Risk level has INCREASED by     " + str( increased_percentage )[0:4] + "%\n")


if len(latest_report_issues) == len(penultumate_report_issues):
    print ("No change in number of issues since last check\n")
elif len (latest_report_issues) < len(penultumate_report_issues):
    print("    Number of issues has REDUCED by   " + str ( ( len (penultumate_report_issues) - len(latest_report_issues) ) ) )
    reduced_issue_percentage = ( 100 - ( 100 / len(penultumate_report_issues) ) * len (latest_report_issues) )
    print ("    Number of issues has REDUCED by   " + str( reduced_issue_percentage )[0:4] + "%\n")
else:
    print("    Number of issues has INCREASED by   " + str( ( len(latest_report_issues) - len(penultumate_report_issues) ) ) )
    increased_issue_percentage = ( ( ( 100 / len (penultumate_report_issues) ) * len(latest_report_issues) ) - 100 )
    print ("    Number of issues has INCREASED by   " + str( increased_issue_percentage )[0:4] + "%\n")
print ("\n")

    
### penultumate_report_titles is set, so is latest_report_titles, how do I compare them?
new_risk = 0
for latest_title in latest_report_titles:
       
    if latest_title in penultumate_report_titles:
        # This issue was there before, not new
        continue
    else:
        # It's a new issue
        print ("NEW ISSUE in this toolkit run:")
        
        for i in latest_report_issues:
            if i.title == latest_title:
                print ("        " + i.title + ": tool [" + i.tool + "]:     Risk $" + str( f'{i.total_cost:,}' ) + "" )
                print ("        CVSS : " + i.CVSS )
                new_risk = new_risk + i.total_cost

if new_risk is not 0:
    print ("\n    New risk in this tookit run    = $" + str( f'{new_risk:,}'  ) )
                
                
print ("\n")

for pen_title in penultumate_report_titles:
    
    if pen_title in latest_report_titles:
        # This issue is in both, don't mention
        continue
    else:
        print ("ISSUE FIXED before this toolkit run:")
        
        for i in penultumate_report_issues:
            if i.title == pen_title:
                print ("        " + i.title + ": tool [" + i.tool + "]:     Risk $" + str( f'{i.total_cost:,}' ) +"" )

print ("\n\n")
