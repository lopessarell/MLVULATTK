import json
import csv
import os

main_dir = "D:/cvssproj"

with open(main_dir + '/EKITS.csv', newline='') as csvfile:
    EKITSdata = list(csv.reader(csvfile))

with open(main_dir + '/EDB.csv', newline='') as csvfile:
    EDBdata = list(csv.reader(csvfile))

with open(main_dir + '/SYM-malware-threats.csv', newline='') as csvfile:
    SYMmaldata = list(csv.reader(csvfile))
    
with open(main_dir + '/SYM-network-attacks.csv', newline='') as csvfile:
    SYMnetdata = list(csv.reader(csvfile))
    
with open(main_dir + '/exploited_vul.csv', newline='') as csvfile:
    exploittdata = list(csv.reader(csvfile))

with open(main_dir + '/cyberwatchdata.csv', newline='') as csvfile:
    cyberwatch = list(csv.reader(csvfile))
    
with open(main_dir + '/symantec.csv', newline='') as csvfile:
    symantec = list(csv.reader(csvfile))

with open(main_dir + '/zeroday.csv', newline='') as csvfile:
    zeroday = list(csv.reader(csvfile))
#print(EKITSdata)
#exit()
# open a file for writing
vul_data_file = open(main_dir + '/VulnDataVisual.csv', 'w')


def generate_dataset(vul_data_file,vuln_data,year):

    for vul in vuln_data :

        # print(vul.get("impact"))
        # exit()
        cve_data = vul.get("cve")
       # print(cve_data["problemtype"]["problemtype_data"][0]["description"])

        id=cweid=version3=vectorString3=attackVector3=attackComplexity3=privilegesRequired3=userInteraction3=scope3=confidentialityImpact3=integrityImpact3=''
        availabilityImpact3=base_score3=base_severity3=exploitabilityScore3=impactScore3=version2=vectorString2=accessVector2=accessComplexity2=authentication2=''
        confidentialityImpact2=integrityImpact2=availabilityImpact2=base_metrics_score2=severity2=exploitabilityScore2=impactScore2=acInsufInfo2=obtainAllPrivilege2=obtainUserPrivilege2=obtainOtherPrivilege2=userInteractionRequired2=''
        id = cve_data["CVE_data_meta"]['ID']
        if(cve_data["problemtype"]["problemtype_data"][0]["description"]):
            cweid = cve_data["problemtype"]["problemtype_data"][0]["description"][0]["value"]
            
        
        if(vul.get("impact")):
            impact_data = vul.get("impact")
            #print(impact_data)
            ''' if(impact_data.get("baseMetricV3")):

                version3 = impact_data["baseMetricV3"]["cvssV3"]["version"]
                vectorString3 = impact_data["baseMetricV3"]["cvssV3"]["vectorString"]
                attackVector3 = impact_data["baseMetricV3"]["cvssV3"]["attackVector"]
                attackComplexity3 = impact_data["baseMetricV3"]["cvssV3"]["attackComplexity"]
                privilegesRequired3 = impact_data["baseMetricV3"]["cvssV3"]["privilegesRequired"]
                userInteraction3 = impact_data["baseMetricV3"]["cvssV3"]["userInteraction"]
                scope3 = impact_data["baseMetricV3"]["cvssV3"]["scope"]
                confidentialityImpact3 = impact_data["baseMetricV3"]["cvssV3"]["confidentialityImpact"]
                integrityImpact3 = impact_data["baseMetricV3"]["cvssV3"]["integrityImpact"]
                availabilityImpact3 = impact_data["baseMetricV3"]["cvssV3"]["availabilityImpact"]
                base_score3  = impact_data["baseMetricV3"]["cvssV3"]["baseScore"]
                base_severity3 =impact_data["baseMetricV3"]["cvssV3"]["baseSeverity"]

                exploitabilityScore3 = impact_data["baseMetricV3"]["exploitabilityScore"]
                impactScore3 = impact_data["baseMetricV3"]["impactScore"]
            '''


            if (impact_data.get("baseMetricV2")):

                version2 = impact_data["baseMetricV2"]["cvssV2"]["version"]
                vectorString2 = impact_data["baseMetricV2"]["cvssV2"]["vectorString"]
                accessVector2 = getAVvalues(impact_data["baseMetricV2"]["cvssV2"]["accessVector"])
                accessComplexity2 = getACvalues(impact_data["baseMetricV2"]["cvssV2"]["accessComplexity"])
                authentication2 = getATvalues(impact_data["baseMetricV2"]["cvssV2"]["authentication"])
                confidentialityImpact2 = getCIAvalues(impact_data["baseMetricV2"]["cvssV2"]["confidentialityImpact"])
                integrityImpact2 = getCIAvalues(impact_data["baseMetricV2"]["cvssV2"]["integrityImpact"])
                availabilityImpact2 = getCIAvalues(impact_data["baseMetricV2"]["cvssV2"]["availabilityImpact"])
                base_metrics_score2 = impact_data["baseMetricV2"]["cvssV2"]["baseScore"]

                severity2 = replacestrvaltonum(impact_data["baseMetricV2"]["severity"])
                exploitabilityScore2 = impact_data["baseMetricV2"]["exploitabilityScore"]
                impactScore2 = impact_data["baseMetricV2"]["impactScore"]
                acInsufInfo2 = impact_data["baseMetricV2"]["acInsufInfo"]  if(impact_data["baseMetricV2"].get("acInsufInfo"))  else ""
                obtainAllPrivilege2 = 1 if impact_data["baseMetricV2"]["obtainAllPrivilege"] == True else 0
                obtainUserPrivilege2 = 1 if impact_data["baseMetricV2"]["obtainUserPrivilege"] == True else 0
                obtainOtherPrivilege2 = 1 if impact_data["baseMetricV2"]["obtainOtherPrivilege"] == True else 0
                userInteractionRequired2 = impact_data["baseMetricV2"]["userInteractionRequired"] if(impact_data["baseMetricV2"].get("userInteractionRequired"))  else ""
                userInteractionRequired2 = 1 if userInteractionRequired2 == True else 0
                
                EKITS = checkforEKITS(id,EKITSdata)
                EDB =  checkforEKITS(id,EDBdata)
                SYMnet = checkforSYMnet(id,SYMnetdata)
                SYMthreat = checkforSYMmal(id,SYMmaldata)
                exploit = checkforexploit(id,exploittdata)
                cyberwatchexploit = checkforexploitcyberwatch(id,cyberwatch)
                syamntecattk = checkforattacksymantec(id,symantec)
                zerodayattk = checkforattckzeroday(id,zeroday)
                
                expcnt = 0
                expflag = 0
                attkcnt = 0
                attkflag = 0
                
                if(EKITS[0] == True or EDB[0] == True or exploit[0] == True or cyberwatchexploit[0] == True):
                    expflag = 1
                    expcnt = EKITS[1] +  int(exploit[1])
                    expcnt = 1 if  expcnt == 0 else  expcnt
                
                
                #if(EKITS[0] == True or EDB[0] == True or exploit[0] == True or cyberwatchexploit[0] == True):
                # expflag = 'Yes'
                # expcnt = EKITS[1] + EDB[1] + int(exploit[1]) + cyberwatchexploit[1]
                
                #blackmarket = 'No'
                #if(EKITS[0] == True):
                # blackmarket = 'Yes'
                    
                if(SYMnet[0] == True or SYMthreat[0] == True or syamntecattk[0] == True or zerodayattk[0] == True):
                    attkflag = 1
                    attkcnt = SYMnet[1] + SYMthreat[1] + zerodayattk[1]
                    attkcnt = 1 if  attkcnt == 0 else  attkcnt
                    
                print(id) 
                #print(id,cweid,version3,vectorString3,attackVector3,attackComplexity3,privilegesRequired3,userInteraction3,scope3,confidentialityImpact3,integrityImpact3,availabilityImpact3,base_score3,base_severity3,exploitabilityScore3,impactScore3,version2,vectorString2,accessVector2,accessComplexity2,authentication2,confidentialityImpact2,integrityImpact2,availabilityImpact2,base_metrics_score2,severity2,exploitabilityScore2,impactScore2,acInsufInfo2,obtainAllPrivilege2,obtainUserPrivilege2,userInteractionRequired2)
                #vul_data_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" % (id,cweid,version3,vectorString3,attackVector3,attackComplexity3,privilegesRequired3,userInteraction3,scope3,confidentialityImpact3,integrityImpact3,availabilityImpact3,base_score3,base_severity3,exploitabilityScore3,impactScore3,version2,vectorString2,accessVector2,accessComplexity2,authentication2,confidentialityImpact2,integrityImpact2,availabilityImpact2,base_metrics_score2,severity2,exploitabilityScore2,impactScore2,acInsufInfo2,obtainAllPrivilege2,obtainUserPrivilege2,userInteractionRequired2))
                
                vul_data_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" % (year,id,accessVector2,accessComplexity2,authentication2,confidentialityImpact2,integrityImpact2,availabilityImpact2,base_metrics_score2,severity2,exploitabilityScore2,impactScore2,obtainAllPrivilege2,obtainUserPrivilege2,userInteractionRequired2,expflag,expcnt,attkflag,attkcnt))
        
        
def checkforEKITS(id,EKITSdata):
   
    flag=False
    count = 0
    for record in EKITSdata:
        
        if(id.strip() == record[9].strip()):
            count=+1
            flag = True
    
    return [flag,count]
        
def checkforEDB(id,EDBdata):
   
    flag=False
    count = 0
    for record in EDBdata:
        
        if(id.strip() == record[1].strip()):
            count=+1
            flag = True
    
    return [flag,count] 

def checkforSYMnet(id,SYMthreatdata):
   
    flag=False
    count = 0
    for record in SYMthreatdata:
        
        if(id.strip() == record[2].strip()):
            count=+1
            flag = True
    
    return [flag,count] 

def checkforSYMmal(id,SYMmaldata):
   
    flag=False
    count = 0
    for record in SYMmaldata:
        
        if(id.strip() == record[2].strip()):
            count=+1
            flag = True
    
    return [flag,count] 

def checkforexploit(id,exploittdata):
   
    flag=False
    count = 0
    for record in exploittdata:
        
        if(id.strip() == record[0].strip()):
            count = record[2]
            flag = True
    
    return [flag,count] 

def checkforexploitcyberwatch(id,cyberwatch):
   
    flag=False
    count = 0
    for record in cyberwatch:
        
        if(id.strip() == record[0].strip()):
            count =+1
            flag = True
    
    return [flag,count]

def checkforattckzeroday(id,zeroday):
   
    flag=False
    count = 0
    for record in zeroday:
        
        if(id.strip() == record[0].strip()):
            count =+1
            flag = True
    
    return [flag,count]

def checkforattacksymantec(id,symantec):
   
    flag=False
    count = 0
    for record in symantec:
        
        if(id.strip() == record[1].strip()):
            count =+1
            flag = True
    
    return [flag,count]


def replacestrvaltonum(val):
    
    val = val.strip()
    
    if(val == "LOCAL" or val == "LOW" or val == "NONE"):
        val = 0
        
    if(val == "ADJACENT NETWORK" or val == "ADJACENT_NETWORK" or val == "MEDIUM" or val == "SINGLE" or val == "PARTIAL" ):
        val = 1
    
    if(val == "NETWORK" or val == "HIGH" or val == "MULTIPLE" or val == "COMPLETE"):
        val = 1
    
    return val

    
def getAVvalues(val):
    
    val = val.strip()
    
    if (val == "LOCAL"):
        val = 0.395
        
    if (val == "ADJACENT NETWORK" or val == "ADJACENT_NETWORK" ):
        val = 0.646
    
    if(val == "NETWORK"):
        val = 1.0
    
    return val

def getACvalues(val):
    
    val = val.strip()
    
    if (val == "LOW"):
        val = 0.71
        
    if(val == "MEDIUM" ):
        val = 0.61
    
    if(val == "HIGH"):
        val = 0.35
    
    return val

def getATvalues(val):
    
    val = val.strip()
    
    if (val == "MULTIPLE"):
        val = 0.45
        
    if(val == "SINGLE" ):
        val = 0.56
    
    if(val == "NONE"):
        val = 0.704
    
    return val
    
def getCIAvalues(val):
    
    val = val.strip()
    
    if (val == "NONE"):
        val = 0.0
        
    if(val == "PARTIAL" ):
        val = 0.275
    
    if(val == "COMPLETE"):
        val = 0.660
    
    return val
    

for jfile in os.listdir(main_dir):
    if(jfile.endswith('.json')):
        json_filepath = main_dir + '/' + jfile
        print(json_filepath)
        year = json_filepath.split('-')[2].split('.')[0].strip()
       
        with open(json_filepath, 'r',encoding="utf8") as jsonfile:
            jsondata=jsonfile.read()

        vulndata_parsed = json.loads(jsondata)

        #print(vulndata_parsed)

        vuln_data = vulndata_parsed["CVE_Items"]
        generate_dataset(vul_data_file,vuln_data,year)
