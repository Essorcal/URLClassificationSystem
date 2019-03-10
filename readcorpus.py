#!/usr/bin/python

import json, sys, getopt, os

def usage():
  print("Usage: %s --file=[filename]" % sys.argv[0])
  sys.exit()

def main(argv):

  #####################
  #Data Import/Parsing#
  #####################

  file=''
  resultsFile= open("results.txt","w")

  myopts, args = getopt.getopt(sys.argv[1:], "", ["file="])
 
  for o, a in myopts:
    if o in ('-f, --file'):
      file=a
    else:
      usage()

  if len(file) == 0:
    usage()
 
  corpus = open(file, encoding='latin1')
  urldata = json.load(corpus, encoding="latin1")

  maliciousThreshold = 28
  #Threshold for domain age only
  #maliciousThreshold = 15
  
  numMalicious = 0
  numNotMalicious = 0
  numTotal = 0
  numMalCorrect = 0
  numMalIncorrect = 0
  numNotMalCorrect = 0
  numNotMalIncorrect = 0
  Company_List = ['amazon', 'facebook', 'ebay', 'paypal', 'coinbase', 'google', 'apple', 'microsoft', 'twitter', 'youtube', 'yahoo']

  for record in urldata:
 
    # Do something with the URL record data...
    malURL = record["malicious_url"]
    host_len = record["host_len"]
    fragment = record["fragment"]
    url_len = record["url_len"]
    default_port = record["default_port"]
    domain_age_days = record["domain_age_days"]
    tld = record["tld"]
    num_domain_tokens = record["num_domain_tokens"]

    #source: https://stackoverflow.com/questions/51796525/python-parsing-json-file-to-access-values-returning-typeerror
    if(record["ips"] is not None and "geo" in record["ips"][0]):
      geo = record["ips"][0]["geo"]
    if(record["ips"] is not None and "ip" in record["ips"][0]):
      ip = record["ips"][0]["ip"]
    if(record["ips"] is not None and "type" in record["ips"][0]):
      typeVar = record["ips"][0]["type"]
    url = record["url"]
    alexa_rank = record["alexa_rank"]
    query = record["query"]
    file_extension = record["file_extension"]
    registered_domain = record["registered_domain"]
    scheme = record["scheme"]
    path = record["path"]
    path_len = record["path_len"]
    port = record["port"]
    host = record["host"]
    num_path_tokens = record["num_path_tokens"]
    domain_token_list = []
    path_token_list = []
    numTotal += 1

    for x in range(num_domain_tokens):
      domain_token_list.insert(x,record["domain_tokens"][x])
      #print (domain_token_list[x])
  
    for x in range(num_path_tokens):
      path_token_list.insert(x,record["path_tokens"][x])
      #print (path_token_list[x])

      ####################
      #URL Classification#
      ####################
    
    ###############################################Alexa Ranking#####################################
    if (alexa_rank == None) or (int(alexa_rank) >= 1000000):
      alexa_rank_score = 0
    elif (int(alexa_rank) >= 100000) and (int(alexa_rank) < 1000000):
      alexa_rank_score = 3
    elif (int(alexa_rank) >= 10000) and (int(alexa_rank) < 100000):
      alexa_rank_score = 4
    elif (int(alexa_rank) >= 1000) and (int(alexa_rank) < 10000):
      alexa_rank_score = 8
    elif (int(alexa_rank) >= 1) and (int(alexa_rank) < 1000):
      alexa_rank_score = 10
    else:
      alexa_rank_score = 0
          
    #print ('Alexa Rank Score: ',alexa_rank_score)
    ###################################################Alexa Ranking End###################################

    ##################################################Domain Age############################################
    if (int(domain_age_days) < 365):
      domain_age_days_score = 0
    else:
      domain_age_days_score = 15
    #print(domain_age_days_score)
    ################################################Domain Age End##############################################

    ##########################################################File Extension###########################################
    if (file_extension == 'exe') or (file_extension == 'it') or (file_extension == 'de') or (file_extension == 'rar'):
      file_extension_score = 0
      #print (file_extension_score)
    elif (file_extension == 'cgi'):
      file_extension_score = 2
      #print (file_extension_score)
    elif (file_extension is None) or (file_extension == 'swf') or (file_extension == 'jsp') or (file_extension == 'php'):
      file_extension_score = 3
      #print (file_extension_score)
    else:
      file_extension_score = 5
      #print (file_extension_score)
    ################################################File Extension End#########################################

    ##################################################Location#################################################
    if (geo == 'RU'):
      geo_score = 0
      #print (geo_score)
    elif (geo == 'CN'):
      geo_score = 2
    else:
      geo_score = 3
      #print (file_extension_score)
    ##############################################Location End###################################################

    ##########################################Domain Tokens###############################################
    if (num_domain_tokens > 7):
      num_domain_tokens_score = 0
    else:
      num_domain_tokens_score = 2
    ############################################Domain Tokens End###########################################

    ###############################################Query#####################################################
    if (str(query).startswith('cgi-bin') and (query is not None)):
      query_score = 0
    elif (str(query).startswith('cmd=') and (query is not None)):
      query_score = 0
    else:
      query_score = 5
    ###############################################Query End####################################################

    ##################################################TLD######################################################
    if (tld == 'gov'):
      tld_score = 5
    elif ((tld == 'net') or (tld == 'jp') or (tld == 'eu') or (tld == 'fr') or (tld == 'com') or (tld == 'org')):
      tld_score = 3
    else:
      tld_score = 0
    ##############################################TLD END####################################################

    #########################################Compound Rules##################################################
    if ((int(domain_age_days) < 365) and bool(set(domain_token_list).intersection(Company_List))):
      rule_1 = -5
      print("yes")
    else:
      rule_1 = 0
    
    #print (bool(set(domain_token_list).intersection(Company_List)))

    ########################################Compound Rules End###############################################


    ############################################Total Score##############################################################
    totalScore = alexa_rank_score + domain_age_days_score + file_extension_score + geo_score + num_domain_tokens_score + query_score + tld_score + rule_1
    #totalScore = domain_age_days_score
    if (totalScore < maliciousThreshold):
      #print ('Total Score: ',totalScore,' Malicious')
      numMalicious += 1
      #print (url,', 1')
      resultsFile.write(url + ", 1\n")
      if (malURL == 1):
        numMalCorrect += 1
      else:
        #print (totalScore)
        #print(url)
        numMalIncorrect += 1
    else:
      #print (url,', 0')
      resultsFile.write(url + ", 0\n")
      #print ('Total Score: ',totalScore,' Not Malicious')
      numNotMalicious += 1
      if (malURL == 0):
        numNotMalCorrect += 1
      else:
        numNotMalIncorrect += 1
        #print(totalScore)
        #print(url)
    ####################################################Total Score End###################################################
  print ('Number Malicious: ',numMalicious,' ',numMalicious/numTotal*100,'%') 
  print ('Number Not Malicious: ',numNotMalicious,' ',numNotMalicious/numTotal*100,'%')

  print ('Total: ',numTotal)
  if (sys.argv[1] == '--file=train.json'):
    print ('Number Malicious Correct: ',numMalCorrect)
    print ('Number Not Malicious Correct',numNotMalCorrect)
    print ('Number Malicious Incorrect: ',numMalIncorrect)
    print ('Number Not Malicious Incorrect: ',numNotMalIncorrect)
  corpus.close()
  resultsFile.close()
if __name__ == "__main__":
  main(sys.argv[1:])